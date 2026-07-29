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
