# Webshell Scan Review Web

Web review để import kết quả `webshell-scan`, public URL cho đơn vị nhận kết quả, nhập mã truy cập trên giao diện, xem dashboard tổng quan, đi vào chi tiết finding, xem raw/decode layer và ghi chú xử lý ban đầu.

## Chạy

```powershell
cd webshell-scan-docker\review-web
python app.py --host 127.0.0.1 --port 8088
```

Khi chạy lần đầu, app tạo `data/config.json` chứa `admin_key` và in ra Admin URL. Mở `/admin`, nhập `admin_key` trên form rồi import và lấy `URL công khai`, `Mã lãnh đạo` và `Mã reviewer` của từng đợt rà quét. Có thể đặt khóa admin cố định bằng biến môi trường:

```powershell
$env:REVIEW_ADMIN_KEY='your-long-random-admin-key'
python app.py --host 127.0.0.1 --port 8088
```

## Import dữ liệu

- Bắt buộc: một file `.enc` sinh bởi scanner sau khi quét, ví dụ `logs\<out_file>.enc`.

File `.enc` là bundle đã mã hóa AES-GCM, bên trong có findings, gray-zone, thống kê all-files và bằng chứng source của các file nghi ngờ. Scanner chỉ nhúng full source cho file nhỏ, mặc định `<= 512KB`; file lớn sẽ được cắt snippet quanh offset YARA/string hit, mặc định khoảng `8KB` trước/sau mỗi hit, tối đa `24` snippet trên mỗi layer. Web giải mã bundle, dựng dashboard, hiển thị raw/decode hoặc `*_snippet` layer và highlight đúng offset rule hit.

Bundle có giới hạn tổng source/snippet mặc định `100MB`. Nếu một file quá lớn để quét snippet hoặc không lấy được context, finding vẫn được import nhưng sẽ hiển thị thiếu source/evidence tương ứng.

Scanner tự tạo `.enc` mặc định sau mỗi lần quét. Khóa bundle lấy từ biến môi trường `WEBSHELL_REVIEW_BUNDLE_KEY`; nếu chưa đặt, scanner tạo local key tại `config/review-bundle.key`. Web import phải dùng cùng khóa đó.

Sau khi import, gửi cho đơn vị:

- URL công khai dạng `/case/<id>`.
- Mã lãnh đạo để xem dashboard và chi tiết ở chế độ chỉ đọc.
- Mã reviewer để xem, cập nhật trạng thái và ghi chú đánh giá.

Người dùng mở URL, nhập mã trên form, sau đó app cấp cookie phiên `HttpOnly` có thời hạn 8 giờ để xem dashboard và chi tiết. Không đặt mã truy cập trong URL.

## Vì sao chỉ cần file `.enc`?

Các file Excel/CSV truyền thống vẫn có thể được scanner ghi ra để lưu nội bộ, nhưng web review không cần nhận rời từng file. `.enc` gom đủ dữ liệu cần thiết cho luồng public: dashboard, finding, raw/decode layer, rule hit, ghi chú và trạng thái xử lý.

## Mô hình an toàn

- App mặc định bind `127.0.0.1`; khi public nên đặt sau reverse proxy HTTPS.
- Mỗi case có URL công khai `/case/<id>`, mã lãnh đạo chỉ đọc và mã reviewer có quyền cập nhật.
- Trang import dùng `admin_key` riêng, nhập qua form và giữ phiên bằng cookie admin.
- Phiên xem báo cáo và phiên admin dùng cookie `HttpOnly`, `SameSite=Strict`, không đưa mã truy cập vào URL.
- Admin chỉ import `.enc`; web không nhận CSV/XLSX/ZIP rời.
- Bundle `.enc` được mã hóa AES-GCM và kiểm tra schema trước khi import.
- File mẫu chỉ được đọc tĩnh, không execute/dynamic load.
- Evidence được tạo bằng YARA và deobfuscation local từ thư mục scanner hiện có.
