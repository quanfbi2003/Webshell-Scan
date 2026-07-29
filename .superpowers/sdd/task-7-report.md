# Task 7 report

Status: complete

Implemented candidate-aware review bundles without changing `webshell-review-bundle-v1` or legacy report row keys.

- Candidate union now includes findings and gray-zone rows, deduplicated by stable candidate IDs.
- `sources/index.json` records candidate IDs, archive/member metadata, source status/reason, and budget omissions without temporary extraction paths.
- Archive members are read from the archive while the scan extraction directory is still available.
- Optional `benchmark.json` is emitted when `benchmark_report` is provided; scanner passes benchmark records as optional metadata.
- Import accepts gray-only/candidate-only bundles and still rejects empty bundles with no candidate records.
- Existing findings/all-files/gray-zone JSON members remain present.

Checks:

- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_review_bundle_compat.py`
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_archive_benchmark.py`
- Python compile for `libs/review_bundle.py`, `review-web/app.py`, and `webshell-scan.py`
- Related benchmark/evidence/schema checks passed.

Concern: Serena/Pyright reports pre-existing unresolved `cryptography` imports in `review_bundle.py`; local focused execution succeeds.

### Task 7 follow-up verification

- Benchmark metadata now enriches represented findings/gray-zone rows only; benchmark-only rows do not create source candidates.
- Archive candidate identity uses durable archive chain/member metadata and does not persist temporary extraction paths; nested archive member reads are attempted from the original archive while available.
- Review import validates non-empty findings/gray rows or valid source-index candidates, supports candidate-only omitted entries, and rejects empty bundles.
- Duplicate ZIP fixture entries were removed from the compatibility check; app test data/config paths are isolated under the temporary directory.

Covering checks:

- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_review_bundle_compat.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_archive_benchmark.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scanner_evidence.py` — PASS (expected synthetic error logs)
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_report_schema.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_fp_guard.py` — PASS
- `python -m py_compile webshell-scan-docker/libs/review_bundle.py webshell-scan-docker/review-web/app.py webshell-scan-docker/tests/check_review_bundle_compat.py` — PASS
- `git diff --check` — PASS

Infrastructure note: initial local test attempts hit a full C: drive due to a 76 GB codebase-memory cache and could not create temporary SQLite/config files. Clearing that local cache restored space; no repository/database corruption was observed.

Status: follow-up complete.
