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

### Task 5 reviewer follow-up

Status: DONE — fail-closed gaps addressed.

- AST-DF `model_incompatible` now creates explicit partial/model-incompatible evidence; ordinary YARA/deobfuscation/read failures create error/partial evidence and terminal errors rather than clean/skipped results.
- Single/thread/collector paths preserve benchmark records; worker/internal failures return terminal error envelopes and accounting remains strict.
- Focused checks reject tautological score assertions and validate error, partial coverage, stable archive metadata, benchmark preservation, and accounting mismatch handling.
- Existing legacy report columns, decisions, quarantine behavior, defaults, archive budgets, and dependency set remain unchanged.

Follow-up verification:
- `python -m py_compile webshell-scan-docker/webshell-scan.py webshell-scan-docker/tests/check_scanner_evidence.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scanner_evidence.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_fp_guard.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/run-regression.py` — PASS

Concern: the focused check intentionally logs synthetic YARA/worker errors to prove they are terminal and non-clean; this is expected test output.
