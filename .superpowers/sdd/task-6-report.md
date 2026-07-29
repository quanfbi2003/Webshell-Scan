# Task 6 report

## Implemented

- Benchmark rows now fail closed: skipped, unsupported, terminal-error, model-incompatible, and manual-review outcomes are `unknown` with null `legacy_score`/`shadow_score`, an explicit `terminal_status`, and scanner shadow provenance.
- Archive cases select exactly the manifest-declared `member_path` plus `member_sha256`; ambiguous or missing members become unknown rather than selecting an arbitrary member. Archive metadata and all SHA-256 values require 64 hexadecimal characters.
- `--shadow-only` is honored for classification and retained in report-level and row-level provenance; legacy score and shadow score remain separately available.
- Schema checks cover terminal status, unknown score nullability, provenance, archive selection, archive metadata, and hexadecimal digest rejection while preserving exact legacy report column order.
- Regression still requires the benchmark manifest, rejects unrecognized samples, requires positive custom YARA cases, and runs focused checks through subprocesses with `PYTHONPATH`.

## Verification

- Focused schema assertions initially failed on missing `terminal_status`, then passed after the fail-closed implementation.
- Local benchmark command completed with all 11 manifest IDs terminal and no duplicate/missing IDs; unknown rows are reported separately and excluded from TN.
- `check_report_schema.py`: PASS.
- `run-regression.py`: PASS.
- `run-benchmark.py --shadow-only`: PASS; report rows use shadow decisions and include provenance.
- Python compilation passed for the three Task 6 Python files.
- Generated benchmark output was kept outside tracked source under `logs/benchmark-local.json`.
- `git diff --check`: PASS.

## Concerns

- The local scanner emits a model-incompatible/unknown fixture outcome, so coverage remains intentionally partial; no automatic download or quarantine is used.
- Scanner initialization compiles existing local YARA/signature data and uses installed optional dependencies only.
