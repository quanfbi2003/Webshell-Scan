### Task 5 report

Status: DONE

Implemented scanner evidence collection for normal and archive paths. Result envelopes carry `benchmark` records plus per-input `terminal_status` while preserving findings, gray-zone, all-file, and multiprocessing result handling. Shadow score is metadata-only; legacy score, findings, and quarantine behavior remain unchanged. Archive records retain original archive SHA-256, relative member path, member SHA-256, and stable candidate ID after temporary extraction cleanup.

Added minimal terminal accounting with `scheduled`, `completed`, `skipped`, `unsupported`, and `errors`; aggregation asserts `scheduled == completed + skipped + unsupported + errors`. Focused regression covers all terminal states.

Exact verification results:
- `python -m py_compile webshell-scan-docker/webshell-scan.py webshell-scan-docker/tests/check_scanner_evidence.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scanner_evidence.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_fp_guard.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/run-regression.py` — PASS

No quarantine changes observed; temporary archive extraction cleaned up.
