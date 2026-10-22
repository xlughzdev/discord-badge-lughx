# Discord Badge Lughx

Công cụ giúp cày thời gian chơi (playtime) và mở khóa huy hiệu số lượng game đã chơi (games-played badges) trên hồ sơ Discord của bạn.

* **Code By:** [Lughx Omni](https://github.com/xlughzdev)
* **Hỗ trợ / Cộng đồng:** [Tham gia Discord LughxShop](https://discord.gg/lughxshop)

---

## Cách hoạt động

Endpoint phân tích của Discord (`/api/v9/science`) theo dõi những tựa game bạn chơi và thời lượng chơi của từng game. Công cụ này gửi các sự kiện giống hệt như ứng dụng Discord thật (`launch_game` và `running_game_heartbeat`), nhưng với số giờ và danh sách game tùy chỉnh. Discord sẽ chấp nhận các sự kiện này (trả về mã `204`) và cập nhật vào huy hiệu trên hồ sơ của bạn.

* **Trạng thái:** Đang hoạt động tốt và chưa bị fix. Huy hiệu thường mất từ **1–2 ngày** để cập nhật theo chu kỳ của Discord, vì vậy kết quả sẽ không hiện lên ngay lập tức.
* **Bảo mật:** Token và Cookie của bạn chỉ được lưu cục bộ trên máy tính (`science_state.json`) — không có bất kỳ dữ liệu nào bị gửi ra ngoài.
* **Lưu ý quan trọng:** Việc sử dụng công cụ này vi phạm Điều khoản Dịch vụ (ToS) của Discord. Bạn tự chịu trách nhiệm với tài khoản của mình.

---

## Hướng dẫn cài đặt & Sử dụng

Không cần cài đặt thư viện ngoài — chỉ sử dụng thư viện chuẩn của Python (yêu cầu **Python 3.10+**).

1. **Chạy chương trình:**
   ```bash
   python lughx.py