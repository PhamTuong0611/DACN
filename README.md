# Demo Package – Hệ Thống Quét Kiểm Tra TLS/SSL

Gói demo này cung cấp một công cụ quét viết bằng Python để kiểm tra cấu hình TLS/SSL và HTTP headers của các máy chủ web. Công cụ hoạt động cả ở chế độ CLI lẫn UI web tương tác.

## Tổng Quan Hoạt Động

- `scanner`: dịch vụ Python (Typer + aiohttp + Jinja2) cung cấp cả CLI lẫn UI web. Scanner sẽ:
  - đọc danh sách domain/URL từ người dùng,
  - kết nối TLS để truy xuất thông tin chứng chỉ SSL/TLS,
  - phân tích thông tin bảo mật (protocol version, cipher strength, certificate validity),
  - xuất kết quả dưới nhiều định dạng (JSON, CSV, Markdown),
  - cung cấp giao diện web tương tác cho việc quét và xuất báo cáo.

## Cấu Trúc Thư Mục

```
docker-compose.yml          # Định nghĩa stack Docker
run_demo.sh                 # Script build và khởi động nhanh (Linux/macOS)
scanner/                    # Mã nguồn ứng dụng quét (Python)
  ├─ scanner.py             # Điểm vào CLI/UI (Typer app)
  ├─ ui_template.html       # Giao diện web Jinja2
  ├─ config.yaml            # Cấu hình quét (timeout, concurrency, v.v.)
  ├─ Dockerfile             # Cấu hình container
  ├─ requirements.txt        # Thư viện Python cần cài
  ├─ modules/               # Logic phân tích và xử lý
  │  ├─ tls_engine.py       # Kết nối TLS, thu thập cert info
  │  ├─ fetcher.py          # Quét async các target
  │  ├─ input_manager.py    # Xử lý input domain/URL
  │  ├─ reporter.py         # Tổng hợp và hiển thị kết quả
  │  ├─ exporter.py         # Xuất báo cáo (JSON, CSV, Markdown)
  │  ├─ config.py           # Tải cấu hình YAML
  │  └─ ...
  └─ partials/              # (Thư mục hỗ trợ)
reports/                    # Thư mục lưu trữ báo cáo (được mount từ Docker)
tests/                      # Test cases
  ├─ test_tls_security.py   # Unit tests
  └─ conftest.py            # Pytest configuration
```

## Yêu Cầu

- Docker và Docker Compose.
- Kết nối Internet để tải image nginx và các thư viện Python.
- Hoặc chạy trực tiếp trên máy: Python 3.8+, pip, các thư viện trong `requirements.txt`.

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
   https://google.com
   ```
3. Nhấn **Quét cấu hình** (hoặc nút tương ứng trên UI).
4. Xem kết quả hiển thị với thông tin:
   - **TLS Protocol**: phiên bản TLS (TLSv1.2, TLSv1.3, v.v.)
   - **Cipher Suite**: tên cipher, protocol, độ dài key
   - **Chứng chỉ SSL**: subject, issuer, ngày hết hạn, SAN
5. Nhấn **Xuất báo cáo** để tải kết quả dưới định dạng:
   - JSON (dữ liệu định hình)
   - CSV (bảng tính)
   - Markdown (tài liệu)

## Chạy Bằng CLI

Bạn có thể sử dụng container scanner để chạy quét từ dòng lệnh:

```bash
# Quét một domain
docker compose exec scanner python scanner.py scan --target https://example.com:443

# Quét nhiều domain cùng lúc
docker compose exec scanner python scanner.py scan \
  --target https://example.com \
  --target https://google.com \
  --target https://github.com

# Quét và xuất báo cáo
docker compose exec scanner python scanner.py scan \
  --target https://example.com \
  --export json,csv,markdown \
  --output-dir ./reports
```

**Tùy chọn CLI:**
- `--target URL` (có thể lặp lại): URL hoặc domain cần quét
- `--export FORMAT`: Định dạng xuất (json, csv, markdown) - có thể kết hợp bằng dấu phẩy
- `--output-dir PATH`: Thư mục lưu báo cáo (mặc định: `./reports`)

## Ghi Chú & Sự Cố Thường Gặp

- **Sai chứng chỉ khi truy cập từ máy khác**: Do container có hostname khác, trình duyệt có thể cảnh báo chứng chỉ không hợp lệ. Bỏ qua hoặc sử dụng `localhost` khi chạy cục bộ.
- **Quét khi chỉnh sửa code**: Nếu sửa file trong `scanner/modules/`, Docker Compose với volume mount sẽ tự cập nhật. Chỉ cần refresh UI hoặc gọi lại CLI.
- **Port 8080 đã sử dụng**: Thay đổi port trong `docker-compose.yml` hoặc chạy trực tiếp: `python scanner.py serve --port 9000`.
- **Kết nối bị từ chối khi quét domain ngoài**: Đảm bảo firewall cho phép kết nối ra cổng 443 (HTTPS).
- **Timeout quá ngắn**: Tăng giá trị `timeout` trong `config.yaml` nếu quét domain chậm.

## Chạy Trực Tiếp (Không Docker)

```bash
cd scanner
pip install -r requirements.txt
python scanner.py scan --target https://example.com
# Hoặc khởi động UI
python scanner.py serve --host 127.0.0.1 --port 8080
```

## Kiến Trúc Ứng Dụng

- **scanner.py**: Typer app với 2 commands chính:
  - `scan`: Chế độ CLI để quét từ dòng lệnh
  - `serve`: Chế độ web server với UI Jinja2
- **modules/tls_engine.py**: Kết nối TLS bằng socket + ssl, truy xuất thông tin chứng chỉ
- **modules/fetcher.py**: Xử lý async quét nhiều target đồng thời
- **modules/exporter.py**: Xuất dữ liệu thành JSON, CSV, Markdown
- **ui_template.html**: Giao diện web tương tác (form nhập + bảng kết quả)

## Chạy Tests

```bash
docker compose exec scanner pytest tests/
# Hoặc cục bộ
pytest tests/
```

Chúc bạn khám phá vui vẻ!
