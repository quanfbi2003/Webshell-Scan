### Task 5 report

Status: DONE_WITH_CONCERNS

Implemented scanner evidence collection for normal and archive paths. Result envelopes now carry `benchmark` records and terminal status while preserving findings, gray-zone, all-file, and multiprocessing result handling. Shadow score is computed only for evidence metadata; legacy score and quarantine/finding thresholds remain unchanged. Archive records retain original archive SHA-256, relative member path, member SHA-256, and stable candidate ID after temporary extraction cleanup.

Focused check passes:
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scanner_evidence.py`

Concerns: worker scheduling/aggregation counters are not fully refactored to assert `scheduled == completed + skipped + unsupported + errors`; existing multiprocessing envelope is preserved, but this requirement needs a follow-up task. Full FP/regression suite and compile should be run before merge.
