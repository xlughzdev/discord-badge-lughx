#!/usr/bin/env python3
"""
discord science lughx - làm tăng thời gian chơi (playtime) và huy hiệu số game đã chơi (games-played badges).

Lughx Omni
https://github.com/xlughzdev

gửi các sự kiện launch_game và running_game_heartbeat tới /api/v9/science, cùng
endpoint mà client thật sử dụng để tính thời gian chơi. duration_tracked_ms không
bị kiểm tra xác thực nên bất kỳ con số nào cũng được chấp nhận thẳng.

chạy:
    python lughx.py

thông tin xác thực (auth bits):
    token            token tài khoản của bạn, nhập ở lần chạy đầu tiên            [đã lưu]
    cookie           cf_clearance, dán thủ công qua tùy chọn menu 2               [đã lưu]
    fingerprint      tùy chọn, chỉ dùng cho bộ đếm số game đã chơi                [đã lưu]
    analytics_token  lấy từ GET /users/@me?with_analytics_token=true, được lưu đệm
    super_props      từ cordapi.dolfi.es (dự phòng: cục bộ)                       [mỗi lần chạy]
    heartbeat/launch các uuid ngẫu nhiên, làm mới mỗi lần chạy                    [mỗi lần chạy]

Việc này vi phạm điều khoản dịch vụ (ToS) của Discord. tài khoản của bạn, bạn tự chịu trách nhiệm !!!
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import webbrowser
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence

# các đường dẫn
ROOT = Path(__file__).resolve().parent
GAMES_FILE = ROOT.parent / "data" / "games.json"     # danh sách game đầy đủ, tự tải xuống nếu chưa có
STATE_FILE = ROOT / "science_state.json"             # token, cookie, thông tin xác thực lưu đệm

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"  # super_props hiện tại, dự phòng cục bộ
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"  # được sử dụng nếu chưa có file games.json
SUBSCRIBE_URL = "https://discord.gg/lughxshop"
DISCORD_INVITE_LABEL = "discord.gg/lughxshop"
DISCORD_INVITE_URL = "https://discord.gg/lughxshop"
GATE_WAIT = 10            # số giây chờ trước khi phím Enter được chấp nhận ở mỗi bước thiết lập

BATCH_SIZE = 50           # số sự kiện trên mỗi request tới /science
BATCH_DELAY = 0.3         # số giây nghỉ giữa các request
AUTH_MAX_AGE = 12 * 3600  # lấy lại analytics token khi bộ nhớ đệm cũ hơn thời gian này
DEBUG = False

# định danh client
CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)


def _user_id_from_token(token: str) -> str:
    # token discord bắt đầu bằng base64(user_id) trước dấu chấm đầu tiên
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    """chạy trình tạo bằng powershell và trả về chuỗi base64 executable_fingerprint."""
    if os.name != "nt":
        raise RuntimeError("tính năng tạo fingerprint chỉ hỗ trợ trên Windows")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "lỗi khi chạy powershell")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("trình tạo không trả về kết quả")
    return out[-1]


class Console:
    """xuất kết quả ra màn hình console có màu."""

    RED = "\x1b[91m"
    ORANGE = "\x1b[38;5;208m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    RESET = "\x1b[0m"
    RULE = "─" * 44

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # các ký tự biểu tượng phải được mã hóa ngay cả khi stdout được chuyển hướng (piped)
        except Exception:
            pass
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
        # bật xử lý thiết bị đầu cuối ảo (virtual terminal) để hiển thị màu ANSI trên Windows
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # handle đầu ra tiêu chuẩn (std_output_handle)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} "
              f"{self.GREY}·{self.RESET} {color}{detail}{self.RESET}")

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def sent(self, target: str, detail: str) -> None:
        self._line(f"{self.GREY}·{self.RESET} {self.GREEN}đã gửi{self.RESET}", target, detail, self.GREEN)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}")

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}")

    def clear(self) -> None:
        # xóa màn hình + lịch sử cuộn, đưa con trỏ về đầu (khi xử lý VT đã bật)
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def banner(self) -> None:
        self.clear()
        print()
        print(f"  {self.ORANGE}lughx{self.RESET} {self.GREY}·{self.RESET} {self.WHITE}huy hiệu discord{self.RESET}")
        print(f"    {self.GREY}by Lughx Omni{self.RESET}")
        print()


@dataclass
class State:
    """thông tin xác thực được lưu trữ: token, cookie, fingerprint và analytics token đã lưu đệm."""

    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = None  # danh sách ID game đã nhận, xoay vòng để tránh trùng lặp
    total_games_claimed: int = 0  # tổng số game tích lũy đã nhận trong phiên này
    total_hours_claimed: float = 0.0  # tổng số giờ tích lũy đã nhận trong phiên này
    subscribed: bool = False  # đã hoàn thành bước youtube một lần
    joined_discord: bool = False  # đã hoàn thành bước discord một lần

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            state = cls(**{k: data.get(k, v) for k, v in cls().__dict__.items() if k != "used_games"})
            state.used_games = data.get("used_games", [])
            return state
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def _local_props() -> dict:
    # thuộc tính client dự phòng nếu không kết nối được cordapi (số bản dựng có thể bị cũ)
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": CLIENT_VERSION,
        "os_version": OS_VERSION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    # cordapi trả về các thuộc tính client mới nhất (giữ cho số bản dựng luôn cập nhật);
    # chèn thêm ID phiên (session ID) của chúng ta để đồng nhất với các sự kiện gửi đi.
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json", "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    # token mà /science thực sự dùng để xác thực; chỉ cần một lệnh gọi REST cơ bản để lấy nó
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token,
        "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token bị từ chối ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("không tìm thấy analytics_token trong phản hồi")
    return token


def ensure_token(state: State, super_props: str) -> None:
    """lấy và lưu đệm analytics token nếu chưa có hoặc đã quá hạn."""
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    """định danh client cho mỗi lần chạy: các uuid mới + super_props, tạo mới mỗi khi khởi động, không lưu lại."""

    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))


@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str


def _win_exe(game: dict) -> str:
    for entry in game.get("executables", []):
        if entry.get("os") == "win32" and entry.get("name"):
            return entry["name"]
    return "game.exe"


def _download_games() -> str:
    request = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass  # lưu đệm tối đa có thể; thư mục chỉ đọc cũng không ngăn cản việc sử dụng dữ liệu
    return raw


def _parse_games(raw: str) -> list[Game]:
    data = json.loads(raw)
    games: list[Game] = []
    seen: set[str] = set()
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games


def load_games() -> list[Game]:
    # ưu tiên file đã lưu đệm, nhưng tải lại nếu bị thiếu, trống hoặc hỏng
    raw = ""
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8").strip()
    if raw:
        try:
            games = _parse_games(raw)
            if games:
                return games
        except (json.JSONDecodeError, ValueError):
            pass  # bộ nhớ đệm bị hỏng, chuyển sang tải mới hoàn toàn
    try:
        return _parse_games(_download_games())
    except Exception:
        return []


class ScienceClient:
    """tạo và gửi các sự kiện launch_game và running_game_heartbeat."""

    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        # client thật sử dụng bộ đếm tăng dần xuyên suốt toàn bộ phiên
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name,
            "game_id": game.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": game.exe,
            # để trống (null) voice/guild/perf - giống thật khi "không ở trong kênh thoại" và tránh làm giả dữ liệu định danh
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            # fingerprint thực tế lấy từ science_state.json; gắn liền với người dùng, không thể làm giả
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, game: Game, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id,
                "game_name": game.name,
                "game_metadata": None,
                "game_executable": game.exe,
                "game_detection_enabled": True,
                "initial_heartbeat": initial,
                "final_heartbeat": final,
                "game_session_id": session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int) -> list[dict]:
        # luồng hoạt động của client thật: mở heartbeat (0ms) -> launch_game -> đóng heartbeat (toàn bộ thời lượng).
        # cả hai heartbeat dùng chung một game_session_id; dấu thời gian trải dài theo thời lượng khi hợp lý.
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0: # thời lượng quá lớn để lùi ngày tháng một cách hợp lý
            start = now
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        """gửi một lô sự kiện. trả về mã trạng thái HTTP (204 = được chấp nhận)."""
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if DEBUG:
            print("\n" + "=" * 72)
            print(f"POST {SCIENCE_URL} ({len(payload['events'])} sự kiện)")
            print("headers:", json.dumps(headers, indent=2))
            print("body:", json.dumps(payload, indent=2))
            print("=" * 72)
        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


def _chunked(items: Sequence[Game], size: int) -> Iterator[Sequence[Game]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class Lughx:
    """gửi các sự kiện theo từng lô và ghi log tiến trình."""

    def __init__(self, client: ScienceClient, console: Console) -> None:
        self.client = client
        self.console = console

    def run(self, games: Sequence[Game], build_events) -> int:
        # build_events(game) -> danh sách các dict sự kiện cần gửi cho game đó
        total = len(games)
        sent_ok = 0
        for request_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events = []
            for game in chunk:
                events.extend(build_events(game))
            status = self.client.post(events)
            if status == 204:
                sent_ok += len(chunk)
                self.console.sent(f"lô {request_no}", f"{sent_ok}/{total} game")
            elif status in (401, 403):
                self.console.err(f"lô {request_no}",
                                 f"[{status}] xác thực bị từ chối · hãy làm mới (tùy chọn 2) với cookie mới")
                return sent_ok
            else:
                self.console.warn(f"lô {request_no}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        return sent_ok


class App:
    def __init__(self) -> None:
        self.console = Console()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []

    # khởi động

    def _flush_stdin(self) -> None:
        # bỏ qua các phím bấm trong lúc đếm ngược để việc nhấn Enter sớm không làm bỏ qua bước chờ
        try:
            if sys.platform == "win32":
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getwch()
            else:
                import termios
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass

    def _gate_step(self, step: int, total: int, action: str, label: str, url: str, done: str) -> None:
        C = self.console
        C.rule()
        C.info(f"{C.ORANGE}bước {step} / {total}{C.WHITE} · {action} {C.ORANGE}{label}{C.WHITE} để tiếp tục")
        C.rule()
        C.info("đang mở trên trình duyệt của bạn...")
        webbrowser.open(url)
        for left in range(GATE_WAIT, 0, -1):
            print(f"\r  {C.GREY}có thể tiếp tục sau {left} giây...{C.RESET}  ", end="", flush=True)
            time.sleep(1)
        print("\r" + " " * 40 + "\r", end="")
        self._flush_stdin()
        input(f"  {C.ORANGE}›{C.RESET} nhấn enter sau khi bạn đã {done} ")
        print()

    def _gate(self) -> None:
        # (cờ trạng thái, hành động, nhãn, url, trạng thái hoàn thành) - hiển thị theo thứ tự, mỗi bước chỉ hiện cho đến khi vượt qua một lần
        steps = [
            ("subscribed", "đăng ký kênh", "youtube.com/@xlughz", SUBSCRIBE_URL, "đăng ký"),
            ("joined_discord", "tham gia", DISCORD_INVITE_LABEL, DISCORD_INVITE_URL, "tham gia"),
        ]
        total = len(steps)
        for i, (flag, action, label, url, done) in enumerate(steps, 1):
            if getattr(self.state, flag):
                continue
            self._gate_step(i, total, action, label, url, done)
            setattr(self.state, flag, True)
            self.state.save()
        self.console.ok("thiết lập", f"đã hoàn thành {total} bước · cảm ơn bạn!")
        time.sleep(0.5)

    def start(self) -> None:
        self.console.banner()
        time.sleep(0.8)
        print()

        if not (self.state.subscribed and self.state.joined_discord):
            self._gate()

        # bước 1: token
        C = self.console
        if not self.state.has_token:
            self._prompt_token()
        else:
            C.ok("xác thực", "đã tải token")
            time.sleep(0.5)
        if not self.state.has_token:
            C.err("token", "bắt buộc phải có để chạy")
            return

        # bước 2: cookie
        if not self.state.has_cookie:
            self.console.banner()
            self._prompt_cookie()
        else:
            C.ok("xác thực", "đã tải cookie")
            time.sleep(0.5)
        if not self.state.has_cookie:
            C.err("cookie", "bắt buộc phải có để chạy")
            return

        # bước 3: danh sách game
        self.console.banner()
        print()
        C.info("đang tải danh sách game...")
        time.sleep(0.4)
        self.games = load_games()
        if not self.games:
            C.err("game", "không thể tải danh sách game")
            C.info(f"đã thử tại {GAMES_FILE} và {GAMES_CDN_URL}")
            C.info("vui lòng kiểm tra kết nối mạng, hoặc đặt file games.json hợp lệ vào đường dẫn trên")
            return
        C.ok("game", f"đã tải {C.ORANGE}{len(self.games)}{C.WHITE} game")
        time.sleep(0.5)

        # bước 4: cảnh báo fingerprint
        if not self.state.fingerprint:
            print()
            C.warn("fingerprint", "chưa thiết lập · script có thể không được tính huy hiệu")
            time.sleep(0.5)

        # bước 5: xác thực
        print()
        C.info("đang kiểm tra xác thực...")
        self._new_session()  # tạo định danh client mới cho lần chạy này
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            C.err("token", str(exc))
            return
        C.ok("xác thực", "sẵn sàng")
        time.sleep(0.5)

        print()
        self.menu()

    def _new_session(self) -> None:
        self.session = Session.new()
        self.client = ScienceClient(self.state, self.session)

    # xác thực

    def _prompt_token(self) -> None:
        self.console.info("dán token tài khoản discord của bạn")
        entered = input(f"  {self.console.GREY}token:{self.console.RESET} ").strip()
        if entered:
            self.state.token = entered
            self.state.save()
            self.console.ok("token", "đã lưu")
            time.sleep(1.5)

    def _prompt_cookie(self) -> None:
        self.console.info("dán cookie cf_clearance của bạn")
        entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
        if entered:
            self.state.cookie = entered
            self.state.save()
            self.console.ok("cookie", "đã lưu")
            time.sleep(1.5)

    def _refresh(self) -> None:
        self.console.info("cập nhật cookie mới? [y/n]")
        choice = input(f"  {self.console.GREY}›{self.console.RESET} ").strip().lower()
        if choice in ("y", "yes", "c", "co"):
            self.console.info("dán cookie mới vào đây")
            entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
            if entered:
                self.state.cookie = entered
                self.console.ok("cookie", "đã cập nhật")
            else:
                self.console.info("giữ nguyên cookie cũ")

        self.console.info("đang làm mới analytics token...")
        try:
            self.state.fetched_at = 0          # ép buộc lấy lại token mới
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            self.console.err("xác thực", str(exc))
            return
        self._new_session()
        self.state.save()
        self.console.ok("xác thực", "đã làm mới")
        time.sleep(1.5)

    def _require_ready(self) -> bool:
        if not self.state.has_cookie:
            self.console.err("cookie", "chưa thiết lập · dùng tùy chọn 2 để thêm")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.console.err("xác thực", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    # các mô-đun chức năng

    def claim_games(self) -> None:
        """nhận thời gian chơi cho các game đã chọn. yêu cầu nhập số lượng game và số giờ."""
        if not self._require_ready():
            return
        C = self.console
        print()
        C.info(f"hiện có {C.GREEN}{len(self.games)}{C.WHITE} game khả dụng")

        # yêu cầu nhập số lượng game
        raw_count = input(f"  {C.GREY}số lượng game muốn cày? [tất cả]:{C.RESET} ").strip()
        try:
            count = int(raw_count) if raw_count else len(self.games)
        except ValueError:
            C.err("nhập liệu", "số lượng không hợp lệ")
            return
        count = min(count, len(self.games))

        # yêu cầu nhập số giờ
        raw_hours = input(f"  {C.GREY}số giờ mỗi game? [1]:{C.RESET} ").strip()
        try:
            hours = float(raw_hours) if raw_hours else 1.0
        except ValueError:
            C.err("nhập liệu", "số giờ không hợp lệ")
            return

        # chọn game: ưu tiên game chưa dùng, xoay vòng qua các game đã dùng nếu cần
        selected = self._select_games(count)
        if not selected:
            C.err("game", "chưa chọn được game nào")
            return

        duration_ms = int(hours * 3600 * 1000)
        total_hours = len(selected) * hours
        print()
        C.info(
            f"đang cày {C.ORANGE}{hours:g}h{C.WHITE} cho "
            f"{C.ORANGE}{len(selected)}{C.WHITE} game "
            f"{C.GREY}·{C.WHITE} tổng cộng {total_hours:,.0f}h"
        )
        C.rule()
        ok = Lughx(self.client, self.console).run(
            selected,
            lambda g: self.client.build_session(g, duration_ms),
        )
        print()
        C.ok("hoàn tất", f"{ok}/{len(selected)} game · đã nhận {ok * hours:,.0f}h")
        # cộng dồn thống kê
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += ok * hours
        self.state.save()
        
        C.rule()
        input(f"  {C.ORANGE}›{C.RESET} nhấn enter để tiếp tục")
        C.rule()

    def _select_games(self, count: int) -> list[Game]:
        """chọn N game, ưu tiên các game chưa dùng và xoay vòng các game đã dùng để tránh lặp lại."""
        available_ids = {g.id for g in self.games}
        unused_ids = [g.id for g in self.games if g.id not in self.state.used_games]
        used_ids = [gid for gid in self.state.used_games if gid in available_ids]

        # nếu có đủ game chưa dùng thì lấy từ danh sách đó
        if len(unused_ids) >= count:
            selected_ids = unused_ids[:count]
        else:
            # lấy hết các game chưa dùng, sau đó xoay vòng qua các game đã dùng
            selected_ids = unused_ids
            if used_ids:
                remaining = count - len(selected_ids)
                rotated = used_ids[remaining:] + used_ids[:remaining]
                selected_ids.extend(rotated[:remaining])

        # lưu theo dõi cho lần chạy tiếp theo
        self.state.used_games = [gid for gid in self.state.used_games if gid not in selected_ids] + selected_ids

        # ánh xạ ngược lại thành các đối tượng Game
        id_map = {g.id: g for g in self.games}
        return [id_map[gid] for gid in selected_ids if gid in id_map]

    # bảng chọn (menu)

    def set_fingerprint(self) -> None:
        C = self.console
        uid = _user_id_from_token(self.state.token)
        if not uid:
            C.err("fingerprint", "chưa có token hợp lệ · hãy cài đặt token trước")
            time.sleep(1.5)
            return
        if os.name != "nt":
            C.err("fingerprint", "tính năng này chỉ hỗ trợ trên Windows")
            time.sleep(1.5)
            return
        C.info("tạo executable_fingerprint gắn với tài khoản + máy tính này")
        C.info(f"tài khoản: {C.ORANGE}{uid}{C.RESET}")
        C.info("nhập đường dẫn tới file .exe của game (hoặc PID của game đang chạy)")
        entered = input(f"  {C.GREY}đường dẫn exe hoặc pid:{C.RESET} ").strip().strip('"')
        if not entered:
            C.info("đã hủy")
            time.sleep(1)
            return
        pid = int(entered) if entered.isdigit() else 0
        path = "" if pid else entered
        if path and not Path(path).exists():
            C.err("fingerprint", f"không tìm thấy file: {path}")
            time.sleep(1.5)
            return
        C.info("đang tạo...")
        try:
            fp = generate_fingerprint(uid, path=path, pid=pid)
        except Exception as exc:
            C.err("fingerprint", str(exc))
            time.sleep(2)
            return
        self.state.fingerprint = fp
        self.state.save()
        C.ok("fingerprint", f"đã thiết lập ({len(fp)} ký tự) · đã lưu vào {STATE_FILE.name}")
        time.sleep(1.5)

    def menu(self) -> None:
        C = self.console
        while True:
            C.clear()
            C.banner()
            print()
            # hiển thị thống kê
            C.info(f"đã tải {C.ORANGE}{len(self.games)}{C.WHITE} game")
            C.info(f"đã cày {C.ORANGE}{self.state.total_games_claimed}{C.WHITE} game · tổng cộng {C.ORANGE}{self.state.total_hours_claimed:,.0f}h{C.WHITE}")
            C.rule()
            C.info(f"{C.ORANGE}1{C.RESET} · cày giờ chơi game")
            C.info(f"{C.ORANGE}2{C.RESET} · làm mới xác thực")
            C.info(f"{C.ORANGE}3{C.RESET} · cài đặt fingerprint")
            C.info(f"{C.ORANGE}4{C.RESET} · thoát")
            C.rule()
            choice = input(f"  {C.ORANGE}›{C.RESET} ").strip()
            print()
            if choice == "1":
                self.claim_games()
            elif choice == "2":
                self._refresh()
            elif choice == "3":
                self.set_fingerprint()
            elif choice in ("4", ""):
                break
            else:
                C.warn("nhập liệu", "lựa chọn không hợp lệ")


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        Console().warn("thoát", "đã dừng chương trình")


if __name__ == "__main__":
    main()