# Demo Package – Hệ Thống Quét Sai Sót Mã Hóa

Gói demo này cung cấp một công cụ quét viết bằng Python để kiểm tra cấu hình TLS/HTTP headers của các máy chủ. Công cụ hoạt động cả ở chế độ CLI lẫn UI web.

## Tổng Quan Hoạt Động

- `scanner`: dịch vụ Python (Typer + aiohttp + Jinja2) cung cấp cả CLI lẫn UI web. Scanner sẽ:
  - đọc danh sách domain/URL,
  - truy xuất thông tin HTTP headers và TLS,
  - phân tích các vấn đề bảo mật,
  - tổng hợp kết quả thành bảng và báo cáo.

## Cấu Trúc Thư Mục

```
docker-compose.yml       # Định nghĩa stack Docker
run_demo.sh              # Script build và khởi động nhanh (Linux/macOS)
scanner/                 # Mã nguồn ứng dụng quét (Python)
  ├─ scanner.py          # Điểm vào CLI/UI
  ├─ ui_template.html    # Giao diện web
  ├─ modules/            # Logic phân tích, gọi SSLyze, v.v.
  └─ requirements.txt    # Thư viện Python cần cài
```

## Yêu Cầu

- Docker và Docker Compose.
- Kết nối Internet để tải image nginx và các thư viện Python.

## Khởi Chạy Nhanh

```bash
chmod +x run_demo.sh
./run_demo.sh
```

Script sẽ build container scanner và chạy Docker Compose với log hiển thị. Lần đầu chạy có thể mất vài phút để cài các thư viện Python.

## Tự Thực Hiện Thủ Công

1. Build container scanner: `docker compose build`
2. Khởi chạy toàn bộ stack: `docker compose up`
3. Dừng dịch vụ khi xong: `docker compose down`

## Sử Dụng Giao Diện Web

1. Mở trình duyệt tới `http://localhost:8080`.
2. Nhập danh sách domain/URL (mỗi dòng một mục). Ví dụ:
   ```
   https://example.com:443
   https://another-domain.com
   ```
3. Nhấn **Quét cấu hình**.
4. Mở rộng từng mục trong bảng kết quả để xem:
   - Thông tin TLS (protocol, cipher, chứng chỉ)
   - Các phát hiện từ header
   - Gợi ý cải thiện

## Chạy Bằng CLI

Bạn có thể sử dụng container scanner để chạy CLI thay vì UI:

```bash
docker compose exec scanner python scanner.py scan --target https://example.com:443
```

Tùy chọn `--target` có thể lặp lại nhiều lần. Kết quả sẽ in ra terminal.

## Ghi Chú & Sự Cố Thường Gặp

- Khi truy cập từ máy ngoài Docker, đảm bảo host name khớp với chứng chỉ hoặc dùng trình duyệt bỏ qua cảnh báo.
- Sau khi chỉnh sửa mã nguồn trong `scanner/`, Docker Compose với volume mount sẽ tự cập nhật khi bạn refresh UI.

Chúc bạn khám phá vui vẻ!
