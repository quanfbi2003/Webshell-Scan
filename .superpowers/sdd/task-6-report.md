# Task 6 report

## Implemented

- Added `tools/run-benchmark.py` with manifest validation, scanner invocation without quarantine, terminal status handling, fail-closed ID accounting, evidence/score/hash/archive fields, metrics, JSON report writing, and legacy report column constants.
- Added `tests/check_report_schema.py` covering required benchmark fields, archive metadata, duplicate IDs, and exact legacy column order.
- Updated `tests/run-regression.py` to require the benchmark manifest, reject unrecognized samples, require positive custom YARA cases, and run focused checks through subprocesses with `PYTHONPATH`.

## Verification

- Local benchmark command completed with all 11 manifest IDs terminal and no duplicate/missing IDs.
- Benchmark metrics: TP=8, FP=0, TN=2, FN=0, coverage=0.9091, unknown_rate=0.0909, gray_zone=1. The unknown case is reported separately and is not counted as TN.
- `check_report_schema.py`: PASS.
- `run-regression.py`: PASS, including evidence, manifest, metrics, policy, model, scanner, schema, FP guard, scan-policy, and AST-DF focused checks.
- Python compilation passed for the three Task 6 Python files.
- Generated benchmark output was kept outside tracked source under `logs/benchmark-local.json`.

## Concerns

- The local scanner emits a model-incompatible/unknown fixture outcome, so coverage is intentionally partial; no automatic download or quarantine was used.
- Scanner initialization compiles the existing local YARA/signature data and uses installed optional dependencies only.
