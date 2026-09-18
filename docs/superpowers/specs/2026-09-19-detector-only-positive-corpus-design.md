# Detector-Only Positive Corpus Benchmark Design

**Date:** 2026-09-19

## Goal

Đo độc lập khả năng đánh dấu của từng detector trên 3.705 mẫu quarantine tại Ubuntu `10.144.8.234`, không quarantine, không gọi kết quả là recall nếu corpus chưa có ground-truth webshell labels.

## Scope

### Detector-only runs

Tạo các run riêng cho:

- `hash_ioc`
- `filename_ioc`
- `entropy`
- `source_sink`
- `behavior_graph`
- `webshell_capability`
- `ast_df`
- `ssdeep`
- `yara_deobfuscated` (raw YARA + deobfuscation layers)

Mỗi run chỉ bật một detector scoring mục tiêu. File read/hash/archive identity/Java triage vẫn giữ ở mức pipeline cần thiết; các detector scoring khác không chạy và không tạo score/evidence.

### Measurement semantics

- `evidence_hit`: detector mục tiêu tạo score/evidence dương.
- `threshold_detected`: legacy decision đạt production threshold.
- `clean_or_missed`: input terminal completed nhưng detector không tạo evidence hit.
- `unknown`: manual review, model incompatible, archive/backend uncertainty hoặc thiếu kết quả.
- `errors`: terminal scanner error, gồm input watchdog timeout.

Các số này là **detector hit counts**, không phải recall/precision/TP/FP/TN nếu corpus chưa có nhãn ground truth.

### Safety and isolation

- Chạy trên Ubuntu `10.144.8.234`.
- Corpus: `/home/antt/webshell-test/scanner/quarantine`.
- Mỗi run dùng isolated output directory, không sửa corpus và không bật quarantine.
- `--workers auto` là mặc định.
- Batch checkpoint 250 input để không mất kết quả đã hoàn tất.
- Không thực thi sample, không ghi source bytes/credential/private key vào report.
- AST-DF chỉ được coi là trusted khi artifact hash/metadata validation pass. Hash bypass chỉ được phép trong isolated experimental report có `trusted=false`.

## Architecture

### Runtime selector

Thêm optional selector `detector_only` vào effective policy/runtime args. `None` giữ legacy behavior. Helper `detector_enabled(name)` trả true khi selector rỗng hoặc trùng detector mục tiêu.

Gate các scoring branches trong normal-file và archive-member paths bằng selector. Legacy score trong detector-only mode chỉ phản ánh detector mục tiêu; `evidence_hit` là tiêu chí chính của detector-only report. Archive identity, terminal accounting, Java triage, cache và timing vẫn được giữ.

Detector-specific requirements:

- `hash_ioc`: hash generation cần thiết để lookup.
- `filename_ioc`: filename/path matching.
- `entropy`: file read + entropy only.
- `source_sink`, `behavior_graph`, `webshell_capability`: gọi đúng heuristic mục tiêu.
- `ast_df`: model validation/load/predict; mismatch/missing là unknown, không fallback clean.
- `ssdeep`: fuzzy hash/compare và signature index.
- `yara_deobfuscated`: raw + deobfuscation layers, YARA cache và tổng timeout per input; không chạy các detector khác.

### Batch runner

`run_positive_corpus()` nhận `detector_only`, `batch_size=250`, `worker_count`, enumerate sorted paths, gọi `scan_path(input_paths=batch_paths)`, normalize result rows, rồi atomically ghi checkpoint JSON sau mỗi batch. Output schema:

```json
{
  "schema": "webshell-detector-only-v1",
  "detector": "behavior_graph",
  "root": "...",
  "worker_count": 24,
  "quarantine": false,
  "checkpoint": {"completed": 250, "total": 3705},
  "completed": false,
  "counts": {
    "evidence_hit": 0,
    "threshold_detected": 0,
    "clean_or_missed": 0,
    "unknown": 0,
    "errors": 0
  },
  "member_counts": {},
  "timing": {},
  "cache": {},
  "archive": {},
  "java_triage": {}
}
```

Khi đủ 3.705 input, `completed=true`. Mỗi detector có output riêng.

### YARA and deobfuscation

YARA-only giữ raw layer và deobfuscation layers theo policy, ghi raw/deobfuscated match counts, layer count, cache hits/misses và timeout. Tổng YARA wall-clock budget áp dụng cho toàn input, không phải reset độc lập cho từng layer.

### AST-DF

Artifact phải được copy vào isolated run ở `models/ast_df.pkl` và pass:

- artifact version;
- feature names/hash;
- extractor version;
- dataset hash;
- model hash;
- positive label/class ordering;
- threshold/language.

Nếu dùng hash bypass để chẩn đoán, report phải có `experimental=true`, `hash_bypass=true`, `trusted=false` và không được dùng làm production baseline.

## Report and aggregation

Mỗi report ghi:

- input-level evidence hit/threshold/clean-or-missed/unknown/error;
- archive-member hit counts và stable archive identity;
- Java triage action/status/reason counts;
- cache counters;
- detector timing seconds/calls/avg_ms;
- worker count thực tế và policy fingerprint;
- `quarantine=false`;
- watchdog/YARA timeout reasons.

Không tính classification metrics nếu không có labels. Khi có labels sau này, có thể map `evidence_hit` vào recall/precision evaluation riêng.

## Verification

Focused checks phải xác nhận:

1. Selector bật đúng detector và tắt các detector scoring khác.
2. Legacy mode không đổi khi selector rỗng.
3. Evidence hit không phụ thuộc production threshold.
4. YARA raw+deobfuscation provenance và timeout tổng.
5. AST-DF trusted/bypass semantics.
6. Batch checkpoint, resume-safe output và terminal accounting.
7. Không quarantine và không source execution.

Remote verification gồm compile, focused checks, detector-only runs và report invariant validation. Local tests/builds không chạy nếu project policy hiện tại không cho phép.
