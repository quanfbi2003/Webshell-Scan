# Webshell Detection Quality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an auditable benchmark and shadow evidence/fusion path that measures webshell recall and false positives while preserving the current scanner decisions until release gates pass.

**Architecture:** Keep the existing detector APIs and legacy CSV/XLSX schemas. Add focused stdlib modules for candidate identity, evidence records, benchmark validation/metrics, and policy validation; collect raw evidence in both normal-file and archive-member paths; write a separate `benchmark.json` sidecar/optional bundle member; compute behavioral fusion only in shadow mode until a locked labeled test split proves it safe. Use the verified Ubuntu host only as a remote verification target, never as a source of secrets or a reason to bypass local tests.

**Tech Stack:** Python 3.10+ stdlib (`argparse`, `hashlib`, `json`, `pathlib`, `statistics`, `tempfile`, `zipfile`, `tarfile`, `time`); existing YARA/cryptography runtime; existing scanner and review-bundle code; Paramiko/SSH client on the developer machine for remote verification only; no new mandatory runtime dependency.

## Global Constraints

- Keep `webshell-review-bundle-v1` and existing CSV/XLSX column names/order unchanged.
- Keep `shadow_mode` enabled by default and `behavioral_fusion_enabled` disabled by default.
- Do not let shadow evidence/fusion trigger, suppress, quarantine, or delete files.
- Do not execute samples or dynamically load decoded payload classes.
- Do not allowlist entire directories such as `vendor`, `node_modules`, `uploads`, or `admin`.
- Do not treat skipped, unsupported, unreadable, timeout, incompatible-model, or worker-error cases as TN/clean.
- Use stable SHA-256/path/archive/member identity; never use temporary extraction paths as durable IDs.
- Store benchmark/evidence metadata in `benchmark.json`/JSONL, not by changing the legacy report columns.
- Keep `webshell-scan-docker/config/scan-policy.json` and `webshell-scan-docker/libs/scan_policy.py` aligned.
- Do not write SSH passwords, private keys, tokens, or other secrets into the repository, plan, logs, command arguments, or remote artifacts.
- Remote verification target: host `10.144.8.234`, user `antt`, isolated checkout `/home/antt/webshell-test-run`; obtain credentials from an interactive secret source/environment at execution time, never from this plan.
- Never modify or delete the existing `/home/antt/webshell-test` data tree during verification.
- Run the local tests before remote tests; a remote failure is reported as a real failure, not hidden by local success.

---

## File map

Create these focused units:

- `webshell-scan-docker/libs/evidence.py`: typed-dict-like plain dictionaries and pure helpers for evidence events, candidate identity, decision reason codes, and behavioral fusion.
- `webshell-scan-docker/libs/benchmark.py`: benchmark manifest validation, case status accounting, metrics, threshold sweep, and JSON serialization.
- `webshell-scan-docker/tools/run-benchmark.py`: explicit offline runner for a manifest; never invoked automatically during a normal scan.
- `webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl`: small labeled manifest for existing regression samples, with fixed SHA-256 and family values.
- `webshell-scan-docker/tests/check_benchmark_manifest.py`: fail-closed manifest checks.
- `webshell-scan-docker/tests/check_benchmark_metrics.py`: pure metrics checks.
- `webshell-scan-docker/tests/check_report_schema.py`: legacy report schema checks.
- `webshell-scan-docker/tests/check_model_metadata.py`: AST-DF metadata/class-ordering checks.
- `webshell-scan-docker/tests/check_archive_benchmark.py`: archive identity and budget checks.
- `webshell-scan-docker/tests/check_parallel_equivalence.py`: canonical result/invariant checks.
- `webshell-scan-docker/tests/check_review_bundle_compat.py`: old bundle and optional benchmark member checks.

Modify only the existing integration points required by the tasks:

- `webshell-scan-docker/webshell-scan.py`: collect evidence in normal/archive paths, preserve legacy score, emit shadow benchmark records, pass canonical archive metadata, and retain current quarantine behavior.
- `webshell-scan-docker/libs/scan_policy.py`: validate supported policy keys/types/ranges and compute policy hash/effective snapshot.
- `webshell-scan-docker/config/scan-policy.json`: aligned shadow/fusion/quarantine policy defaults.
- `webshell-scan-docker/libs/ast_df.py`: model metadata, positive-class handling, feature compatibility checks, and explicit incompatible status.
- `webshell-scan-docker/tools/train-ast-df.py`: family-disjoint train/calibration/test split, threshold selection, artifact metadata, safe ZIP handling.
- `webshell-scan-docker/libs/review_bundle.py`: include candidate-aware source entries and optional `benchmark.json` without breaking v1 members.
- `webshell-scan-docker/review-web/app.py`: accept gray-only candidate bundles while preserving old bundle behavior.
- `webshell-scan-docker/tests/run-regression.py`: require manifest IDs and run the complete local check suite.
- `webshell-scan-docker/config/review-bundle.key`: do not add or commit replacement secrets; deployment documentation must prefer external injection and rotation.

---

### Task 1: Add pure evidence and candidate identity helpers

**Files:**
- Create: `webshell-scan-docker/libs/evidence.py`
- Create: `webshell-scan-docker/tests/check_evidence.py`

**Interfaces:**
- `make_evidence(detector, score=0, reason=None, layer="raw", coverage="full", truncated=False, status="clean", rule_version=None, model_version=None) -> dict`
- `canonical_candidate_id(run_id, file_sha256, canonical_path, archive_sha256=None, archive_chain=(), member_path=None, member_sha256=None) -> str`
- `fuse_behavioral_scores(scores: dict, ratio: float, cap: int) -> int`
- `decision_reason(evidence_groups: set[str], total_score: int, min_score: int, gray_min: int, yara_timeout=False, coverage="full") -> str`

- [ ] **Step 1: Write failing pure-helper checks**

Create the check with exact assertions:

```python
from libs.evidence import canonical_candidate_id, fuse_behavioral_scores, make_evidence

assert make_evidence("source_sink", 55, "hit")["detector"] == "source_sink"
assert make_evidence("ast_df", status="model_incompatible")["status"] == "model_incompatible"
assert canonical_candidate_id("run-1", "a" * 64, "/tmp/a") != canonical_candidate_id("run-2", "a" * 64, "/tmp/a")
assert canonical_candidate_id(
    "run", "a" * 64, "/tmp/a", "b" * 64, ("outer.war",),
    "WEB-INF/Shell.class", "c" * 64,
)
assert fuse_behavioral_scores(
    {"source_sink": 55, "behavior_graph": 72, "ast_df": 80}, 0.25, 100
) == 100
try:
    fuse_behavioral_scores({"source_sink": 1}, 1.1, 100)
except ValueError:
    pass
else:
    raise AssertionError("ratio outside [0, 1] must fail")
print("evidence checks passed")
```

The implementation must make every assertion pass; no conditional or non-assertive placeholder is permitted.

- [ ] **Step 2: Run the check and verify it fails**

Run from repository root:

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_evidence.py
```

Expected: `ModuleNotFoundError: No module named 'libs.evidence'`.

- [ ] **Step 3: Implement pure helpers**

Use only deterministic dictionaries and strings. Normalize path separators to `/`; include all identity components in a length-delimited hash input so `archive_chain` and member paths cannot collide. `fuse_behavioral_scores` must ignore non-positive scores, reject ratio outside `[0, 1]`, and cap the result. `decision_reason` must return stable codes such as `entropy_only`, `filename_only`, `fuzzy_hash_only`, `behavioral_single_evidence`, `manual_review_yara_timeout`, `coverage_partial`, or `below_report_threshold`.

- [ ] **Step 4: Run the check and compile**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_evidence.py
python -m py_compile webshell-scan-docker/libs/evidence.py webshell-scan-docker/tests/check_evidence.py
```

Expected: `evidence checks passed`, exit code `0`.

- [ ] **Step 5: Commit**

```bash
git add webshell-scan-docker/libs/evidence.py webshell-scan-docker/tests/check_evidence.py
git commit -m "feat: add structured evidence helpers"
```

Commit body must end with:

```text
Co-Authored-By: Claude <noreply@anthropic.com>
```

---

### Task 2: Add fail-closed benchmark manifest and metrics

**Files:**
- Create: `webshell-scan-docker/libs/benchmark.py`
- Create: `webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl`
- Create: `webshell-scan-docker/tests/check_benchmark_manifest.py`
- Create: `webshell-scan-docker/tests/check_benchmark_metrics.py`

**Interfaces:**
- `load_cases(path: str, root: str) -> list[dict]`
- `validate_case(case: dict, root: str) -> None`
- `record_result(case: dict, status: str, predicted: str | None, score: int | None, **metadata) -> dict`
- `compute_metrics(results: list[dict]) -> dict`
- `threshold_sweep(results: list[dict], thresholds: list[int]) -> list[dict]`
- `write_jsonl(path: str, rows: list[dict]) -> None`

- [ ] **Step 1: Add fixture manifest with all current samples**

Use the existing 11 files under `webshell-scan-docker/tests/samples/`. Assign `webshell` to `source_sink_*` and `obfusc_*`, `benign` to `benign_*` and `clean_hello.php`; use explicit `language`, `family`, `archive: false`, and the SHA-256 values verified on the local checkout. No sample may be silently ignored because its filename prefix is unknown.

- [ ] **Step 2: Write failing manifest/metrics checks**

The checks must assert duplicate ID rejection, invalid label rejection, SHA-256 mismatch rejection, missing expected ID detection, and that `error`/`skipped`/`unsupported` are not TN. Use a small in-memory set with one TP, one FP, one TN, one FN, and one error; assert `TP=1`, `FP=1`, `TN=1`, `FN=1`, `coverage=4/5`, and `unknown_rate=1/5`.

- [ ] **Step 3: Run checks and verify failure**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_manifest.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_metrics.py
```

Expected: import/implementation failure before the module exists.

- [ ] **Step 4: Implement validation and metrics**

Require fields `id`, `path`, `label`, `language`, `sha256`, and `family`; require `archive`, `member_path`, and `member_sha256` when `archive` is true. Validate SHA-256 with `hashlib.sha256`. Metrics must use only completed `detected`/`clean` outcomes for confusion counts; gray-zone is reported separately and unknown statuses are excluded from TN. Threshold sweep must never mutate the locked result list.

- [ ] **Step 5: Run checks and compile**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_manifest.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_benchmark_metrics.py
python -m py_compile webshell-scan-docker/libs/benchmark.py
```

Expected: both checks print `passed`, exit code `0`.

- [ ] **Step 6: Commit**

```bash
git add webshell-scan-docker/libs/benchmark.py webshell-scan-docker/tests/fixtures/benchmark webshell-scan-docker/tests/check_benchmark_manifest.py webshell-scan-docker/tests/check_benchmark_metrics.py
git commit -m "test: add labeled benchmark manifest and metrics"
```

---

### Task 3: Validate policy and add shadow defaults

**Files:**
- Modify: `webshell-scan-docker/libs/scan_policy.py:7-120`
- Modify: `webshell-scan-docker/config/scan-policy.json`
- Create: `webshell-scan-docker/tests/check_policy_validation.py`
- Modify: `webshell-scan-docker/tests/check_scan_policy_defaults.py`

**Interfaces:**
- `validate_scan_policy(policy: dict) -> dict`
- `policy_sha256(policy: dict) -> str`
- `load_scan_policy(app_path, logger=None) -> dict` remains the public loader.

- [ ] **Step 1: Write failing validation checks**

Assert that valid shadow/fusion defaults load, ratio `-0.1` and `1.1` are rejected, a non-integer score cap is rejected, and unknown behavior keys do not become active policy. Assert JSON and `DEFAULT_POLICY` keys/values remain aligned.

- [ ] **Step 2: Implement validation and aligned defaults**

Add exactly:

```json
{
  "shadow_mode": true,
  "behavioral_fusion_enabled": false,
  "behavioral_corroboration_ratio": 0.25,
  "behavioral_fusion_cap": 100,
  "quarantine_requires_confirmed": true
}
```

Validate booleans, non-negative integer caps, score thresholds, ratio `[0, 1]`, and known keys. Canonicalize JSON with sorted keys before hashing. Preserve existing fallback behavior for an absent policy file, but return validated defaults.

- [ ] **Step 3: Run local checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_policy_validation.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scan_policy_defaults.py
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add webshell-scan-docker/libs/scan_policy.py webshell-scan-docker/config/scan-policy.json webshell-scan-docker/tests/check_policy_validation.py webshell-scan-docker/tests/check_scan_policy_defaults.py
git commit -m "feat: validate shadow scan policy"
```

---

### Task 4: Add AST-DF artifact metadata and safe inference

**Files:**
- Modify: `webshell-scan-docker/libs/ast_df.py`
- Modify: `webshell-scan-docker/tools/train-ast-df.py`
- Create: `webshell-scan-docker/tests/check_model_metadata.py`

**Interfaces:**
- `build_model_metadata(model, feature_names, extractor_version, dataset_hash, threshold, language=None) -> dict`
- `_predict_probability(model, vector, positive_label=1) -> float` must use `classes_` when available.
- `ast_df_heuristic(...) -> tuple[int, str | None]` retains its existing signature and returns no score plus explicit internal status on incompatible artifacts.

- [ ] **Step 1: Write failing model checks**

Use a fake model with `classes_ = [1, 0]` and probabilities `[0.9, 0.1]`; assert the probability for positive label `1` is `0.9`, not index `1`. Assert feature hash mismatch, missing metadata, and missing model remain no-model/incompatible outcomes without raising from the scanner. Assert the existing no-model self-check still returns `(0, None)`.

- [ ] **Step 2: Implement metadata and positive-class handling**

Persist model plus metadata in a versioned local artifact envelope. Verify `feature_names`, feature hash, extractor version, positive label, threshold, and optional language before inference. Reject malformed metadata, unknown class ordering, and unsupported language compatibility. Do not execute or import samples.

- [ ] **Step 3: Make training split/calibration explicit**

Update the training tool to require `train`, `calibration`, and `test` family-disjoint inputs or deterministic split metadata. Select threshold only from calibration data, lock it before test evaluation, and write metrics plus dataset/model hashes. Keep ML dependencies training-only.

- [ ] **Step 4: Harden explicit ZIP dataset handling**

Replace unbounded `extractall` with member path validation, maximum file count/bytes, download timeout, archive size limit, and optional SHA-256 verification. Abort on unsafe members rather than extracting them.

- [ ] **Step 5: Run local checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_model_metadata.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_ast_df.py
python -m py_compile webshell-scan-docker/libs/ast_df.py webshell-scan-docker/tools/train-ast-df.py
```

Expected: all checks pass. Training help must still work when sklearn/deepforest is absent; actual training is skipped unless dependencies and a vetted dataset are present.

- [ ] **Step 6: Commit**

```bash
git add webshell-scan-docker/libs/ast_df.py webshell-scan-docker/tools/train-ast-df.py webshell-scan-docker/tests/check_model_metadata.py
 git commit -m "feat: validate ast-df model metadata"
```

---

### Task 5: Integrate evidence collection into normal and archive scans

**Files:**
- Modify: `webshell-scan-docker/webshell-scan.py:93-115, 1080-1344, 1391-1425, 1513-2081`
- Create: `webshell-scan-docker/tests/check_scanner_evidence.py`

**Interfaces:**
- `Scanner._new_evidence_record(...) -> dict` or equivalent helper using `libs.evidence.make_evidence`.
- `Scanner._finalize_candidate_evidence(...) -> dict` produces `legacy_score`, `shadow_score`, `evidence_groups`, `primary_evidence`, `legacy_decision`, `shadow_decision`, `status`, and `coverage`.
- Existing `process_single_file_with_result` result envelope gains `benchmark` records while preserving `findings`, `gray_zone`, and `all_file_info`.

- [ ] **Step 1: Write failing integration checks**

Assert normal-file and archive paths both produce evidence records with the same detector names, `legacy_score` remains unchanged in shadow mode, and archive records retain archive/member SHA-256/member path after temporary extraction cleanup. Assert no evidence-only result moves a file to quarantine.

- [ ] **Step 2: Refactor score collection minimally**

Replace immediate behavioral additions with raw score collection. Preserve each existing reason string and legacy group cap. Calculate the shadow fused score only after all detectors have run. When `shadow_mode` is true, leave `total_score`, main/gray decisions, and quarantine checks on the legacy path.

- [ ] **Step 3: Add explicit coverage/status events**

Record YARA timeout, AST-DF incompatibility, read errors, deobfuscation truncation, and head/tail heuristic windows as status/coverage metadata. Do not convert these states to clean.

- [ ] **Step 4: Add stable archive metadata**

Hash the original archive before extraction, retain member relative path and member bytes/hash, pass nested archive chain through recursion, and stop using temporary extracted absolute paths as durable IDs. Keep current archive extraction budgets and traversal checks.

- [ ] **Step 5: Preserve multiprocessing terminal results**

Add a per-input result envelope with terminal status. Record worker errors rather than only logging them. Assert `scheduled == completed + skipped + unsupported + errors` before aggregating results.

- [ ] **Step 6: Run local integration checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scanner_evidence.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_fp_guard.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/run-regression.py
```

Expected: all pass; current report column names/order unchanged.

- [ ] **Step 7: Commit**

```bash
git add webshell-scan-docker/webshell-scan.py webshell-scan-docker/tests/check_scanner_evidence.py
git commit -m "feat: collect shadow evidence in scanner"
```

---

### Task 6: Add benchmark runner and report schema guard

**Files:**
- Create: `webshell-scan-docker/tools/run-benchmark.py`
- Create: `webshell-scan-docker/tests/check_report_schema.py`
- Modify: `webshell-scan-docker/tests/run-regression.py`

**Interfaces:**
- `run_case(scanner, case: dict) -> dict`
- `run_manifest(manifest_path: str, root: str, worker_count: int = 1) -> list[dict]`
- `write_benchmark_report(path: str, run: dict) -> None`

- [ ] **Step 1: Write failing runner/schema checks**

Require every manifest ID in the output exactly once. Assert `benchmark.json` contains run ID, legacy/shadow score, status, evidence groups, SHA-256, and archive metadata where applicable. Assert the three legacy column lists exactly match their current names/order.

- [ ] **Step 2: Implement explicit runner**

The runner loads the manifest, invokes the exact scanner path without quarantine, records terminal statuses, computes metrics, and writes JSONL/JSON. It must fail closed on missing/duplicate IDs and never count unknown cases as TN. It must not auto-download data or models.

- [ ] **Step 3: Make one regression command run all checks**

Update `run-regression.py` to require the manifest and invoke the focused checks through subprocesses with `PYTHONPATH` set. Keep direct YARA/source-sink/deobfuscation assertions, but add positive YARA expectations, fail on unrecognized samples, and include check outputs in the final status.

- [ ] **Step 4: Run local benchmark**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tools/run-benchmark.py \
  --manifest webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl \
  --root . --workers 1 --output logs/benchmark-local.json
```

Expected: all 11 fixture IDs are terminal; no missing/duplicate IDs; `unknown` is reported separately; `logs/benchmark-local.json` is generated outside tracked source.

- [ ] **Step 5: Run schema/regression checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_report_schema.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/run-regression.py
```

- [ ] **Step 6: Commit**

```bash
git add webshell-scan-docker/tools/run-benchmark.py webshell-scan-docker/tests/check_report_schema.py webshell-scan-docker/tests/run-regression.py
git commit -m "test: add fail-closed benchmark runner"
```

---

### Task 7: Make review bundles candidate-aware without breaking v1

**Files:**
- Modify: `webshell-scan-docker/libs/review_bundle.py:421-573`
- Modify: `webshell-scan-docker/review-web/app.py` at bundle import handling
- Create: `webshell-scan-docker/tests/check_review_bundle_compat.py`
- Create: `webshell-scan-docker/tests/check_archive_benchmark.py`

**Interfaces:**
- `build_review_zip(..., benchmark_report: dict | None = None) -> tuple[bytes, dict]` retains existing callers through a default.
- Optional ZIP member `benchmark.json`.
- Candidate-aware `sources/index.json` entries contain stable IDs, archive/member metadata, `source_status`, and `source_reason`.

- [ ] **Step 1: Write failing compatibility/archive checks**

Assert an old bundle still decrypts/imports with existing JSON members. Assert a gray-only bundle is accepted by the new importer. Assert an archive member source is present when within budget and explicitly omitted when over budget; never reference a deleted temporary extraction path. Assert optional `benchmark.json` is ignored safely by old readers.

- [ ] **Step 2: Implement candidate union**

Build source/index entries from findings plus gray-zone candidates, deduplicated by stable candidate ID, not absolute temporary path. For archive candidates, store member bytes or explicit omission status within configured total/source budgets. Keep existing `findings.json`, `all_files.json`, and `gray_zone.json` members.

- [ ] **Step 3: Add optional benchmark metadata**

Write the benchmark report as optional `benchmark.json` and add only optional manifest fields. Do not change `SCHEMA = "webshell-review-bundle-v1"` or legacy row keys.

- [ ] **Step 4: Accept gray-only imports**

Update importer validation so a bundle with zero main findings but valid gray/candidate records is not rejected. Preserve old behavior for malformed/empty bundles with no candidate records.

- [ ] **Step 5: Run checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_review_bundle_compat.py
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_archive_benchmark.py
```

Expected: old and new bundle compatibility checks pass; gray-only and archive source status are explicit.

- [ ] **Step 6: Commit**

```bash
git add webshell-scan-docker/libs/review_bundle.py webshell-scan-docker/review-web/app.py webshell-scan-docker/tests/check_review_bundle_compat.py webshell-scan-docker/tests/check_archive_benchmark.py
git commit -m "feat: preserve gray evidence in review bundles"
```

---

### Task 8: Verify multiprocessing/archive equivalence and secure bundle-key handling

**Files:**
- Create: `webshell-scan-docker/tests/check_parallel_equivalence.py`
- Modify: `webshell-scan-docker/libs/review_bundle.py:55-77`
- Add/update deployment documentation outside tracked secrets, for example `docs/superpowers/plans/2026-07-29-webshell-detection-quality.md` only; do not commit a key.

**Interfaces:**
- `canonicalize_benchmark_results(rows: list[dict]) -> list[tuple]`
- `bundle_passphrase(...)` remains compatible with environment injection but rejects empty/known weak values and checks file mode where supported.

- [ ] **Step 1: Write failing equivalence/key checks**

Assert worker-count result sets are equal after canonical sorting, missing/duplicate IDs fail, terminal-status invariant is enforced, and a weak/missing bundle key is rejected. Do not print the key in assertion messages.

- [ ] **Step 2: Implement canonical comparison and key checks**

Compare `(sample_id, member_path, verdict, score, sha256, evidence_groups, status)`. Keep existing key-file compatibility for local use only, but prefer `WEBSHELL_REVIEW_BUNDLE_KEY`; reject weak/default values and document rotation. Never place the key in a bundle or manifest.

- [ ] **Step 3: Run local checks**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_parallel_equivalence.py
```

Expected: pass without requiring a real multi-process scanner run; fixture comparison must cover workers 1 and N envelopes.

- [ ] **Step 4: Commit**

```bash
git add webshell-scan-docker/libs/review_bundle.py webshell-scan-docker/tests/check_parallel_equivalence.py
 git commit -m "test: enforce parallel and bundle key invariants"
```

---

### Task 9: Local full verification and shadow benchmark baseline

**Files:**
- Verify: all files from Tasks 1-8
- Generated untracked output: `webshell-scan-docker/logs/benchmark-local.json` (delete after collecting metrics unless retained as a documented baseline artifact)

- [ ] **Step 1: Compile all changed Python files**

```bash
python -m py_compile \
  webshell-scan-docker/webshell-scan.py \
  webshell-scan-docker/libs/evidence.py \
  webshell-scan-docker/libs/benchmark.py \
  webshell-scan-docker/libs/scan_policy.py \
  webshell-scan-docker/libs/ast_df.py \
  webshell-scan-docker/libs/review_bundle.py \
  webshell-scan-docker/tools/run-benchmark.py \
  webshell-scan-docker/tools/train-ast-df.py
```

Expected: exit code `0`.

- [ ] **Step 2: Run all focused checks**

```bash
set -o pipefail
export PYTHONPATH=webshell-scan-docker
python webshell-scan-docker/tests/check_evidence.py
python webshell-scan-docker/tests/check_benchmark_manifest.py
python webshell-scan-docker/tests/check_benchmark_metrics.py
python webshell-scan-docker/tests/check_policy_validation.py
python webshell-scan-docker/tests/check_model_metadata.py
python webshell-scan-docker/tests/check_scanner_evidence.py
python webshell-scan-docker/tests/check_report_schema.py
python webshell-scan-docker/tests/check_review_bundle_compat.py
python webshell-scan-docker/tests/check_archive_benchmark.py
python webshell-scan-docker/tests/check_parallel_equivalence.py
python webshell-scan-docker/tests/check_ast_df.py
python webshell-scan-docker/tests/check_fp_guard.py
python webshell-scan-docker/tests/check_scan_policy_defaults.py
python webshell-scan-docker/tests/run-regression.py
```

Expected: every check exits `0`; positive/negative fixture expectations are explicit; no unknown case is misreported as clean.

- [ ] **Step 3: Run the local shadow benchmark**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tools/run-benchmark.py \
  --manifest webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl \
  --root . --workers 1 --shadow-only --output webshell-scan-docker/logs/benchmark-local.json
```

Expected: all IDs terminal, metrics emitted, `behavioral_fusion_enabled=false` and `shadow_mode=true` recorded, no quarantine operation performed.

- [ ] **Step 4: Run benchmark with multiple workers**

```bash
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tools/run-benchmark.py \
  --manifest webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl \
  --root . --workers 2 --shadow-only --output webshell-scan-docker/logs/benchmark-local-workers-2.json
```

Expected: canonical result equality with workers 1, no missing/duplicate IDs.

- [ ] **Step 5: Remove temporary generated outputs**

Delete only generated benchmark outputs created by this plan when they are not selected as a lasting baseline artifact. Do not delete quarantine, decoded samples, logs, or reports that predate this work.

- [ ] **Step 6: Commit verification-only test updates if needed**

```bash
git status --short
git diff --check
git add webshell-scan-docker/tests docs/superpowers/plans/2026-07-29-webshell-detection-quality.md
git commit -m "test: complete webshell quality verification"
```

Do not commit generated logs or any secret.

---

### Task 10: Remote Ubuntu verification on the approved isolated checkout

**Files:**
- No source files are modified by this task.
- Remote checkout: `/home/antt/webshell-test-run`.
- Remote generated outputs: use `/tmp/webshell-quality-run` or another disposable path under `/home/antt`; never `/home/antt/webshell-test`.

**Interfaces:**
- Remote test environment: Ubuntu host `10.144.8.234`, username `antt`.
- Authentication: obtain the password interactively or from a protected local secret/environment; never put it in this plan, repository, shell history, process arguments, or output.
- Remote checkout must be created from the exact Git snapshot under test and must report its commit/archive hash before execution.

- [ ] **Step 1: Verify the remote host and isolated target**

Use an SSH client with host-key verification. Run only:

```bash
hostname
id -un
python3 --version
git --version
pwd
```

Expected: user `antt`, Python 3.10+ and Git available. Confirm `/home/antt/webshell-test-run` is not the existing `/home/antt/webshell-test` data tree. Do not run destructive commands against the latter.

- [ ] **Step 2: Upload the exact source snapshot without secrets**

Create a local `git archive` or clean source tarball from the exact commit/working snapshot. Exclude `.git` credentials, private keys, generated reports, quarantine, logs, model artifacts, and any secret file. Upload to `/home/antt/webshell-test-run` only after checking the directory is the isolated target. Verify a SHA-256 of the archive or spec/source snapshot on both sides.

The remote target must contain the same test fixtures and policy files as local. Do not use `git pull` from an untrusted remote or auto-download dependencies/datasets.

- [ ] **Step 3: Inventory remote dependencies**

```bash
python3 - <<'PY'
mods = ('yara', 'cryptography', 'ssdeep', 'numpy', 'sklearn', 'deepforest')
for name in mods:
    try:
        module = __import__(name)
        print('%s=present' % name)
    except Exception as exc:
        print('%s=missing:%s' % (name, type(exc).__name__))
PY
```

Record missing optional modules. Do not install packages as part of verification unless separately approved; missing SSDeep/ML dependencies must result in explicit skipped capability, not a hidden pass.

- [ ] **Step 4: Run remote syntax and focused checks**

From `/home/antt/webshell-test-run`:

```bash
set -o pipefail
export PYTHONIOENCODING=utf-8
export PYTHONPATH=webshell-scan-docker
python3 -m py_compile \
  webshell-scan-docker/webshell-scan.py \
  webshell-scan-docker/libs/evidence.py \
  webshell-scan-docker/libs/benchmark.py \
  webshell-scan-docker/libs/scan_policy.py \
  webshell-scan-docker/libs/ast_df.py \
  webshell-scan-docker/libs/review_bundle.py \
  webshell-scan-docker/tools/run-benchmark.py
python3 webshell-scan-docker/tests/check_evidence.py
python3 webshell-scan-docker/tests/check_benchmark_manifest.py
python3 webshell-scan-docker/tests/check_benchmark_metrics.py
python3 webshell-scan-docker/tests/check_policy_validation.py
python3 webshell-scan-docker/tests/check_model_metadata.py
python3 webshell-scan-docker/tests/check_scanner_evidence.py
python3 webshell-scan-docker/tests/check_report_schema.py
python3 webshell-scan-docker/tests/check_review_bundle_compat.py
python3 webshell-scan-docker/tests/check_archive_benchmark.py
python3 webshell-scan-docker/tests/check_parallel_equivalence.py
python3 webshell-scan-docker/tests/check_ast_df.py
python3 webshell-scan-docker/tests/check_fp_guard.py
python3 webshell-scan-docker/tests/check_scan_policy_defaults.py
python3 webshell-scan-docker/tests/run-regression.py
```

Expected: every command exits `0`. Record missing dependency failures separately and do not label a skipped optional test as PASS.

- [ ] **Step 5: Run the remote shadow benchmark**

```bash
mkdir -p /tmp/webshell-quality-run
PYTHONPATH=webshell-scan-docker python3 webshell-scan-docker/tools/run-benchmark.py \
  --manifest webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl \
  --root . --workers 1 --shadow-only \
  --output /tmp/webshell-quality-run/benchmark-ubuntu.json
```

Expected: all manifest IDs have terminal results, legacy decisions remain authoritative, `shadow_mode=true`, `behavioral_fusion_enabled=false`, and no quarantine operation occurs.

- [ ] **Step 6: Run remote worker equivalence**

```bash
PYTHONPATH=webshell-scan-docker python3 webshell-scan-docker/tools/run-benchmark.py \
  --manifest webshell-scan-docker/tests/fixtures/benchmark/cases.jsonl \
  --root . --workers 2 --shadow-only \
  --output /tmp/webshell-quality-run/benchmark-ubuntu-workers-2.json
python3 webshell-scan-docker/tests/check_parallel_equivalence.py \
  /tmp/webshell-quality-run/benchmark-ubuntu.json \
  /tmp/webshell-quality-run/benchmark-ubuntu-workers-2.json
```

Expected: canonical result sets match; missing/duplicate/terminal-status invariant passes.

- [ ] **Step 7: Collect remote results without secrets**

Copy back only benchmark JSON/metrics and command output. Before copying, verify they contain no password, private key, environment dump, or bundle key. Report exact exit code and dependency skips. Do not copy quarantine, application data, or unrelated `/home/antt/webshell-test` content.

- [ ] **Step 8: Clean only disposable remote outputs**

After results are copied, remove only `/tmp/webshell-quality-run` and any upload tarball created for this task. Do not remove the isolated checkout unless the user explicitly requests cleanup; do not touch `/home/antt/webshell-test`.

- [ ] **Step 9: Record the remote verification result**

Add the exact remote commit/archive SHA, host label, dependency inventory, test command list, PASS/FAIL/SKIPPED statuses, and benchmark metrics to the final implementation report. Never record the password.

---

### Task 11: Release decision and final verification

**Files:**
- Modify only if needed: `docs/superpowers/plans/2026-07-29-webshell-detection-quality.md` or a separate final benchmark report.
- Do not modify policy to enable fusion automatically.

- [ ] **Step 1: Verify release gates**

Require all of:

- no missing, duplicate, or hash-mismatched benchmark IDs;
- family-disjoint train/calibration/test split;
- explicit TP/FP/TN/FN and unknown rate;
- unchanged hash IOC behavior;
- stable archive/member identity;
- worker 1/N equivalence;
- gray-only bundle acceptance and source status;
- policy/model/rule provenance;
- local and remote checks pass, with optional dependency skips explicitly recorded.

- [ ] **Step 2: Keep fusion disabled when any gate fails**

If a gate fails, leave:

```json
"shadow_mode": true,
"behavioral_fusion_enabled": false
```

Record the failing invariant/metric instead of adjusting a threshold from one sample.

- [ ] **Step 3: Run final local verification**

```bash
git diff --check
PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/run-regression.py
git status --short
```

Expected: no whitespace errors; regression PASS; only intentional source/docs changes remain.

- [ ] **Step 4: Produce final report**

Report:

```text
Đã triển khai:
- structured evidence and stable candidate identity
- fail-closed benchmark and metrics
- shadow behavioral fusion
- archive/multiprocessing invariants
- review-bundle compatibility

Đã verify local:
- exact command and PASS/FAIL/SKIPPED

Đã verify Ubuntu:
- host label and isolated checkout only
- dependency inventory
- exact command and PASS/FAIL/SKIPPED
- benchmark metrics

Chưa bật:
- behavioral_fusion_enabled remains false until release gates pass
- no model training/download if dependencies/dataset are not vetted

Bảo mật:
- password not stored or reported
- existing application data and quarantine untouched
```

---

## Self-review checklist

- Spec coverage: benchmark/ground truth (Tasks 2, 6), stable IDs/archive (Tasks 1, 5, 7), structured evidence/fusion (Tasks 1, 5), decision matrix (Tasks 1, 5), AST-DF calibration/metadata (Task 4), policy validation/provenance (Task 3), bundle compatibility (Task 7), multiprocessing/archive equivalence (Tasks 5, 8), tests/release gates (Tasks 9-11), and Ubuntu verification (Task 10).
- Placeholder scan: no `TBD` or `TODO` implementation markers; all execution paths have concrete commands and expected outcomes.
- Type consistency: evidence helper names/signatures are defined in Task 1 and consumed in Tasks 5/8; benchmark helper names/signatures are defined in Task 2 and consumed in Tasks 6/9/10; bundle `benchmark_report` default is backward-compatible.
- Secret handling: the plan names host/user/isolated directory as requested but never contains or passes a password; credential acquisition is explicitly external and interactive/protected.
- Scope: no source refactor outside evidence/benchmark/policy/AST-DF/archive/bundle integration; no signature database changes; no runtime dependency addition.
