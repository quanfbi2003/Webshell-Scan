# Smart Archive Completion Design

**Date:** 2026-09-18

## Goal

Hoàn thiện các phần còn thiếu của Smart Archive mà không thay đổi quyết định legacy: ghi provenance triage Java đầy đủ, thêm cache memory-only an toàn, xử lý RAR/7Z bằng listing và selective extraction, sau đó chạy benchmark positive corpus trên Ubuntu `10.144.8.234` mà không quarantine.

## Scope

### In scope

1. Java class triage provenance cho mọi `.class` member trong archive.
2. Cache trong bộ nhớ theo từng `Scanner`/worker:
   - cache hash không lưu bytes;
   - cache YARA chỉ dùng lại khi rule set và external context tương đương;
   - cache hit/miss được thống kê.
3. Smart handling cho `.rar` và `.7z`:
   - list trước bằng `7z`;
   - eligibility gate trước khi extract;
   - selective extraction;
   - lỗi listing/backend trả unknown/error và không extract.
4. Positive-corpus benchmark trên Ubuntu, không quarantine, với các mẫu đã xác minh là mã độc.

### Out of scope

- Cache disk/SQLite/IPC giữa workers.
- Thay đổi detector, threshold, legacy score, CSV, review bundle hoặc quarantine policy.
- Tự động suy ra precision/FP/TN từ positive-only corpus.
- Thực thi mẫu hoặc giải mã/chạy mã độc.
- Thêm dependency Python bắt buộc cho RAR/7Z; backend ngoài là lệnh `7z` có sẵn trên Ubuntu.

## Architecture

### Memory cache

Cache là state của `Scanner`, được khởi tạo mới mỗi lần tạo scanner. Worker multiprocessing có cache riêng và không chia sẻ qua `Manager` hay queue. Hash cache lưu tuple hash theo input identity; YARA cache lưu kết quả match serializable nhỏ. Cache key phải bao gồm mọi context có thể ảnh hưởng kết quả, tối thiểu SHA-256, extension, file type, basename/path context và rule/policy fingerprint. Không cache exception hoặc timeout như kết quả sạch. Cache không được làm thay đổi kết quả khi cùng bytes xuất hiện dưới tên/path khác.

Để tránh cache SHA-256 thuần túy làm sai YARA external variables, kết quả YARA chỉ được reuse khi external context tương đương (`filename`, `filepath`, `extension`, `filetype`, `md5`) và compiled rule set của scanner không đổi. Các detector/path decision phụ thuộc path vẫn chạy theo luồng hiện tại.

### Java provenance

`inspect_class_constant_pool` tiếp tục trả triage object gồm `valid`, `status`, `coverage`, `signals`, `reason`. Trong `scan_archive_recursive`, mọi `.class` member đủ điều kiện đều tạo benchmark record triage:

- `candidate`: tiếp tục detector scan và gắn `java_triage` vào record candidate.
- `inventory_only`: không chạy detector nặng; tạo record inventory với `status=unknown`, `terminal_status=completed`, score null và `triage_action=inventory_only`, để không bị tính nhầm là TN.
- `unknown`: tạo record error/unknown với lý do ổn định, không deep-scan tiếp.

Các trường archive identity hiện tại (`archive_sha256`, `archive_chain`, `member_path`, `member_sha256`, `member_extension`, `candidate_id`) vẫn được giữ. Validator benchmark chỉ yêu cầu `java_triage` khi record là Java triage record; schema cũ vẫn hợp lệ.

### RAR/7Z

`SafeArchiveExtractor` thêm nhánh backend dùng `7z l` trước. Output machine-readable phải được parse thành member path, file type và size; path traversal, directory, size/budget và eligibility được kiểm tra trước khi extract. Chỉ member `deep_scan` hoặc nested archive `archive_triage` được đưa vào selective extraction `7z x`; không dùng extract toàn archive. Kết quả extract lại được kiểm tra realpath và budget.

Các lỗi thiếu binary, timeout, encrypted archive, exit code lỗi hoặc listing không parse được đặt `last_error` với reason ổn định và trả danh sách rỗng; caller tạo archive error benchmark record, không extract mù. Archive hợp lệ nhưng không có member đủ điều kiện hoàn tất bình thường, không sinh finding giả.

### Positive-corpus benchmark

Benchmark runner/utility sẽ chạy toàn bộ 3.705 file trên Ubuntu bằng scanner hiện tại, không `--quarantine` và không `--quarantine-exact`. Vì corpus chỉ chứa mẫu dương tính, báo cáo tập trung vào:

- scheduled/completed/skipped/unsupported/errors;
- detected, missed/clean, unknown/error;
- archive members được list/extract/skip;
- Java triage counts và lý do;
- cache hit/miss;
- profile/rule provenance.

Không báo cáo FP/TN/precision nếu không có benign corpus. Benchmark phải lưu output JSON/report ở thư mục run cô lập, không sửa corpus gốc hay thư mục quarantine hiện có.

## Error and compatibility rules

- Legacy normal-file path, score, decisions, findings, gray-zone, CSV, review bundle và quarantine giữ nguyên.
- Cache timeout/exception không trở thành clean hit.
- Temporary extraction paths không xuất hiện trong durable identity/provenance.
- Không ghi credential, command secret, nội dung mẫu hoặc private key vào report.
- `7z` command phải dùng argument list, timeout và giới hạn output; không shell interpolation từ member path.
- Nếu xác thực corpus chỉ là malware nói chung chứ không phải webshell, report phải dùng coverage/detection terminology, không gán nhãn webshell sai.

## Verification

Các check tĩnh/unit nhỏ sẽ bao phủ:

1. Cache hit/miss, context mismatch và timeout không cache.
2. Java safe/candidate/unknown và record provenance cho mọi class member.
3. 7z listing parse, selective member list, traversal/static filtering và malformed listing không extract.
4. Benchmark schema backward compatibility và positive-only metrics.
5. Ubuntu run không quarantine, terminal accounting cân bằng và report có provenance.

Full scan remote chỉ thực hiện sau khi code checks cục bộ và compile/static inspection hoàn tất. Việc xác thực remote dùng SSH target `10.144.8.234` theo cơ chế credential đã được cấp sẵn, không lưu credential trong repository.
