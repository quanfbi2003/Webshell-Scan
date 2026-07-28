# Task 2 report

Status: DONE

## Implemented files

- `webshell-scan-docker/libs/benchmark.py`
  - Added fail-closed JSONL case loading and required-field/label/path/SHA-256 validation.
  - Added result recording, completed-only confusion metrics, unknown/gray-zone accounting, threshold sweeps, and JSONL writing.
- `webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl`
  - Added all 11 existing samples with explicit labels, language, family, archive metadata, and local SHA-256 values.
- `webshell-scan-docker/tests/check_benchmark_manifest.py`
  - Checks manifest coverage, duplicate IDs, invalid labels, hash mismatch rejection, and missing-ID detection.
- `webshell-scan-docker/tests/check_benchmark_metrics.py`
  - Checks TP/FP/TN/FN, coverage/unknown rate, exclusion of error/skipped/unsupported from TN, and non-mutating threshold sweeps.

## Verification

1. RED checks before implementation:
   - `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_manifest.py`
   - `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_metrics.py`
   - Both failed as expected with `ModuleNotFoundError: No module named 'libs.benchmark'`.
2. Required checks after implementation:
   - Manifest: passed, exit code `0`.
   - Metrics: passed, exit code `0`.
3. Compile check:
   - `python -m py_compile webshell-scan-docker/libs/benchmark.py`: passed, exit code `0`.
4. `git diff --check`: passed.

No samples were executed, no downloads or secrets were used, and scanner/policy files were not changed.

## Reviewer fix

- Root cause: the original raw SHA-256 values depended on Git's platform-specific text checkout line endings.
- Added explicit manifest `hash_mode: "text_lf"` and documented validation behavior in `benchmark.py`; hashes now cover canonical LF-normalized text bytes without treating validation errors as clean.
- Added a regression assertion that all 11 cases validate after LF-normalizing their sample bytes.
- Corrected provenance to the actual amended commit `e8d778a`.
- Re-ran manifest, metrics, compile, and diff checks: all passed.

## Commit

Previous Task 2 commit:

- `e8d778a` — `test: add labeled benchmark manifest and metrics`
- Commit trailer: `Co-Authored-By: Claude <noreply@anthropic.com>`

## Concerns

- None for Task 2.
