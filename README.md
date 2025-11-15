# Demo Package – Hệ Thống Quét Sai Sót Mã Hóa

Gói demo này mô phỏng một môi trường nhỏ cùng một công cụ quét viết bằng Python. Mục tiêu là giúp bạn quan sát sự khác biệt cấu hình, cách quét TLS/HTTP headers, và xem báo cáo SSLyze ngay trong giao diện web.

## Tổng Quan Hoạt Động

- `scanner`: dịch vụ Python (Typer + aiohttp + Jinja2) cung cấp cả CLI lẫn UI web. Scanner sẽ:
  - đọc danh sách domain/URL,
  - truy xuất thông tin HTTP headers và TLS,
  - chạy SSLyze trên từng mục tiêu,
  - tổng hợp kết quả thành bảng và báo cáo.

Tất cả dịch vụ nằm trong cùng mạng Docker, nên khi chạy demo bạn có thể nhập trực tiếp `https://nginx_good:8443` hoặc `https://nginx_bad:9443` trong UI.

## Cấu Trúc Thư Mục

```
docker-compose.yml       # Định nghĩa stack gồm 3 container
run_demo.sh              # Script build và khởi động nhanh (Linux/macOS)
scanner/                 # Mã nguồn ứng dụng quét (Python)
  ├─ scanner.py          # Điểm vào CLI/UI
  ├─ ui_template.html    # Giao diện web
  ├─ modules/            # Logic phân tích, gọi SSLyze, v.v.
  └─ requirements.txt    # Thư viện Python cần cài
```

## Yêu Cầu

- Docker và Docker Compose.

## Khởi Chạy Nhanh

```bash
chmod +x run_demo.sh
./run_demo.sh
```

Script sẽ build container scanner, chạy Docker Compose và hiển thị log. Lần đầu chạy có thể mất vài phút để cài thư viện (bao gồm SSLyze 5.x).

## Tự Thực Hiện Thủ Công

1. Build container scanner: `docker compose build`
2. Khởi chạy toàn bộ stack: `docker compose up`
3. Dừng dịch vụ khi xong: `docker compose down`

## Sử Dụng Giao Diện Web

1. Mở trình duyệt tới `http://localhost:8080`.
2. Nhập danh sách domain/URL (mỗi dòng một mục). Ví dụ:
   ```
   (https://classroom.google.com/)
   ```
3. Nhấn **Chạy quét**.
4. Mở rộng từng mục trong bảng kết quả để xem:
   - Thông tin TLS (protocol, cipher, chứng chỉ)
   - Các phát hiện từ header
   - Gợi ý cải thiện
   - Kết quả SSLyze (luôn được chạy cho mỗi mục tiêu)

## Chạy Bằng CLI

Bạn có thể sử dụng container scanner để chạy CLI thay vì UI:

```bash
docker compose exec scanner python scanner.py scan --target https://nginx_good:8443
```

Tùy chọn `--target` có thể lặp lại nhiều lần. Kết quả sẽ in ra terminal.

## Ghi Chú & Sự Cố Thường Gặp

- Nếu SSLyze thiếu hoặc không chạy được, vùng kết quả sẽ hiển thị lỗi cụ thể (ví dụ không tìm thấy binary, hết thời gian, v.v.).
- Khi truy cập từ máy ngoài Docker, đảm bảo host name khớp với chứng chỉ hoặc dùng trình duyệt bỏ qua cảnh báo.
- Sau khi chỉnh sửa mã nguồn trong `scanner/`, Docker Compose với volume mount sẽ tự cập nhật khi bạn refresh UI.

Chúc bạn khám phá vui vẻ!
