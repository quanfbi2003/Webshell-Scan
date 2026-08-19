# Webshell detection quality and false-positive reduction

## Status

Draft for review. This document defines the design and rollout gates; it does not change scanner behavior by itself.

## Goal

Improve webshell detection quality while reducing false positives without silently changing the existing finding, gray-zone, or quarantine behavior.

The first release is measurement-first and runs the new evidence model in shadow mode. The existing scanner remains the source of production decisions until a locked benchmark demonstrates that the new model is safe to enable.

## Scope

This design covers:

- benchmark and ground-truth manifest;
- stable identity for normal files and archive members;
- structured detector evidence and coverage metadata;
- correlated behavioral evidence fusion;
- explicit main-finding, gray-zone, suppressed, and unknown decisions;
- AST-DF model metadata and calibration workflow;
- archive and multiprocessing result invariants;
- review-bundle compatibility and gray-zone evidence;
- policy validation and reproducible run metadata;
- regression, benchmark, and release gates.

It applies to PHP, JSP/JSPX, ASP/ASPX, CFM, and supported script/artifact paths already handled by the scanner.

## Non-goals

- Replacing YARA, hash IOC, SSDeep, source-sink, behavior-graph, capability, or AST-DF detectors.
- Executing samples or introducing dynamic code execution during scanning.
- Treating a machine-learning probability as a calibrated probability before a held-out calibration workflow exists.
- Allowlisting entire directories such as `vendor`, `node_modules`, `uploads`, or `admin`.
- Changing the existing quarantine threshold or enabling new quarantine behavior in the first release.
- Changing the existing CSV/XLSX column names or order.
- Guaranteeing recall or false-positive improvements before a labeled benchmark exists.

## Current constraints

The scanner currently runs several detectors in `webshell-scan-docker/webshell-scan.py` and adds their scores through `_add_group_score`. The normal-file path and `scan_archive_recursive` repeat much of the detector flow independently. Reports currently use these schemas:

- findings: `FILE`, `SHA256`, `SCORE`, `TIME`, `DESCRIPTION`, `EXTENSION`;
- all files: `FILE`, `SHA256`, `TIME_CREATED`, `TIME_MODIFIED`, `TIME_ACCESSED`, `EXTENSION`;
- gray zone: findings columns plus `VIRUSTOTAL_URL`, `VT_CHECKED`, `VT_RESULT`.

`library_fp_gate` and `_single_evidence_gray_reason` already provide partial FP protection. They remain compatible safeguards, but they are not the benchmark or decision model defined here.

The archive extractor already has traversal and decompression budgets. Archive findings currently refer to temporary extracted paths, which are removed before the review bundle is created. The new design must remove that identity dependency.

## Safety and rollout principles

### Shadow mode is the default

Add a policy-controlled shadow mode. In shadow mode the scanner computes structured evidence and a candidate fused score, but:

- the existing score decides main findings;
- the existing gray-zone logic decides gray-zone rows;
- the existing quarantine logic is unchanged;
- the new score cannot cause a file to be moved, deleted, or suppressed.

The shadow result is written to a separate benchmark sidecar and, where supported, to optional bundle metadata. It must not be buried only in the human-readable `DESCRIPTION` field.

### Evidence strength is explicit

The initial decision classes are:

- `confirmed`: hash IOC, or another explicitly configured high-confidence rule after calibration;
- `main_finding`: legacy decision meets the report threshold;
- `gray_zone`: candidate requires review but is not confirmed;
- `suppressed`: known benign/library context with an auditable reason;
- `unknown`: skipped, unsupported, unreadable, timeout, incompatible model, or worker error.

Entropy-only, filename-only, SSDeep-only, AST-DF-only, behavior-graph-only, and capability-only evidence cannot trigger new quarantine behavior. A YARA timeout is manual review, not clean.

### No directory-wide trust

Trusted context may use verified SHA-256, package/version metadata, an integrity manifest, or an explicit scoped allowlist. A basename or directory name alone is never sufficient to suppress a candidate.

## Benchmark manifest

Create a separate manifest for labeled benchmark cases. It is not derived from `all_files_csv`, because that report does not contain every excluded, skipped, failed, or archive-member input.

Each normal-file case contains:

```json
{
  "id": "php-001",
  "path": "tests/samples/source_sink_php.php",
  "label": "webshell",
  "language": "php",
  "sha256": "...",
  "family": "source-sink-basic",
  "archive": false
}
```

Each archive-member case contains:

```json
{
  "id": "war-001-member-002",
  "path": "tests/fixtures/shell.war",
  "label": "webshell",
  "language": "jsp",
  "sha256": "...",
  "family": "behinder-variant",
  "archive": true,
  "member_path": "WEB-INF/classes/Shell.class",
  "member_sha256": "..."
}
```

Validation is fail-closed. The benchmark runner must fail on duplicate IDs, invalid labels, missing paths, SHA-256 mismatch, missing family, missing expected IDs, or a case that ends without a terminal status. A skipped, unsupported, or errored case is recorded as `unknown`; it is never counted as a true negative.

Cases are split by family/variant, not only by file hash, to prevent train/test leakage.

## Stable candidate identity

Every scan gets a `run_id`. A normal-file candidate is identified by:

```text
run_id + file_sha256 + canonical_path
```

An archive member is identified by:

```text
run_id + archive_sha256 + archive_chain + member_path + member_sha256
```

The canonical record retains the original archive SHA-256, member path, member SHA-256, member extension, and nested archive chain. Temporary extraction paths are never used as durable IDs, report keys, benchmark IDs, or review-bundle source references.

Duplicate member names remain separate records when their content or archive identity differs. A duplicate record is an error in the benchmark runner, not an implicit merge.

## Structured detector evidence

Existing detector functions may continue returning `(score, reason)`. The scan pipeline additionally records an internal evidence event for every detector that ran or failed:

```json
{
  "detector": "source_sink",
  "score": 55,
  "reason": "...",
  "layer": "raw",
  "coverage": "full",
  "truncated": false,
  "status": "hit",
  "rule_version": null,
  "model_version": null
}
```

The detector set is:

```text
hash_ioc
filename_ioc
entropy
source_sink
behavior_graph
webshell_capability
ast_df
ssdeep
yara
```

The candidate record also stores `evidence_groups`, `primary_evidence`, `coverage`, `truncated`, `status`, and a stable decision reason code. If a detector sees only a head/tail window, a deobfuscated layer budget, or an output-limited representation, it records partial coverage. No absent match under partial coverage is interpreted as proof of benign content.

Raw detector evidence remains separate even when a fused score is calculated. This preserves investigation detail and permits later re-calibration.

## Behavioral fusion

Only these correlated static behavioral detectors are candidates for fusion:

```text
source_sink
behavior_graph
webshell_capability
ast_df
```

They frequently observe overlapping request, decode, dispatch, execution, file, or network patterns. Their raw scores must be collected before the final score is calculated; `_add_group_score` must not be used to increment the production total before fusion.

The shadow fusion formula is:

```text
primary = max(non-zero behavioral scores)
secondary = sum(other behavioral scores)
fused_behavioral = primary + floor(secondary * corroboration_ratio)
fused_behavioral = min(fused_behavioral, behavioral_fusion_cap)
```

The following policy keys are introduced with safe defaults:

```json
{
  "shadow_mode": true,
  "behavioral_fusion_enabled": false,
  "behavioral_corroboration_ratio": 0.25,
  "behavioral_fusion_cap": 100,
  "quarantine_requires_confirmed": true
}
```

The ratio and cap are tunable parameters, not validated truths. In shadow mode the scanner records `legacy_score`, `shadow_score`, `legacy_decision`, and `shadow_decision`. The new score does not affect the production decision.

Other evidence groups retain their existing caps and remain outside the behavioral fusion family:

```text
hash_ioc + yara + fused_behavioral + entropy + ssdeep + filename_ioc
```

A later release may replace the hand-tuned fusion with a calibrated meta-model, but only after the labeled workflow below has established a locked operating point.

## Decision matrix

The initial decision matrix is:

| Evidence/state | Decision |
|---|---|
| Hash IOC hit | `confirmed` |
| Existing legacy score meets report threshold | `main_finding` |
| Single behavioral signal below its configured main threshold | `gray_zone` |
| Entropy only | `gray_zone` |
| Filename IOC only | `gray_zone` |
| SSDeep only | `gray_zone` |
| YARA timeout | `unknown` with manual-review reason |
| Missing or partial source | `unknown` or `gray_zone` with coverage reason; never clean by omission |
| Library context without direct request-to-exec evidence | `suppressed` or `gray_zone` with audit reason |
| Worker, read, model, or unsupported-extension error | `unknown` |

The current `library_fp_gate` remains in the path. It must emit a structured suppression reason as well as its existing human-readable reason. The current gray-zone behavior remains the production behavior during shadow mode.

When fusion is eventually enabled, quarantine additionally requires a confirmed decision. A heuristic score alone cannot introduce automatic quarantine.

## AST-DF model and calibration

The current AST-DF score is an optional local-model signal, not a calibrated posterior. The training workflow is changed to:

1. fit on the train split;
2. select a threshold on the calibration split;
3. lock the threshold and artifact;
4. evaluate once on the test split;
5. publish metrics and artifact hashes.

The model artifact or adjacent metadata must declare:

```json
{
  "positive_label": 1,
  "feature_names": [],
  "feature_hash": "...",
  "extractor_version": "...",
  "dataset_hash": "...",
  "threshold": 0.78,
  "language": "php",
  "model_sha256": "..."
}
```

Inference validates positive-class ordering (`classes_`), feature ordering/hash, extractor version, model metadata, and language/extension compatibility. A mismatch produces `ast_df_status=model_incompatible` and an `unknown` evidence event; it does not silently count as a clean prediction.

The train tool must use safe archive extraction for explicitly supplied datasets, with path validation, file/byte limits, download timeout, size limit, and checksum support. It must not execute samples and must not auto-download during a scan.

## Policy validation and reproducibility

`load_scan_policy` must validate supported keys, types, and ranges before the effective policy is used. Invalid values fail closed with a clear warning or abort according to severity; arbitrary unknown keys are not treated as active behavior.

Every run records a manifest containing:

```text
run_id
scanner_version
policy_sha256
detector/rule versions
model_sha256 and model metadata hash
scan path
start/end time
worker mode/count
```

The benchmark sidecar and optional bundle manifest include the same provenance. This makes shadow comparisons reproducible.

## Review bundle compatibility

Keep `webshell-review-bundle-v1` and the existing findings/all-files/gray-zone JSON members. Keep the existing CSV/XLSX schemas and column order.

Add an optional `benchmark.json` member and an optional `benchmark` object in `manifest.json`. Existing importers ignore the optional member and continue reading old bundles.

The source index becomes candidate-aware. It includes both main findings and gray-zone candidates. For archive members, the bundle stores member bytes when within source budgets. If bytes are omitted, the record explicitly states:

```text
source_status=omitted
source_reason=member_budget_exceeded|source_not_found|source_read_error
```

A temporary extracted path is never used to claim source availability.

The review workflow must accept gray-only bundles. Existing consumers that require a non-empty findings list remain backward-compatible; the new importer recognizes the candidate/gray collection and does not reject a scan solely because it has no main findings.

The bundle key is not stored in a manifest or bundle. Secret injection is preferred over a committed plaintext key. A weak/default key is rejected, file permissions are checked where supported, and rotation is documented. If the existing key was ever used outside a local disposable environment, it must be rotated before deployment.

## Benchmark metrics

For labeled cases, report:

```text
TP
FP
TN
FN
precision
recall
false-positive rate
false-negative rate
coverage
unknown rate
```

Break down results by language/extension, family, archive versus normal file, raw versus deobfuscated layer, and primary evidence group. Include threshold sweeps and Wilson 95% intervals for small samples.

`skipped`, `unsupported`, and `error` are excluded from TN and reported in `unknown_rate`. A benchmark run fails if any expected ID is missing, duplicated, or silently dropped.

## Multiprocessing and archive equivalence

Run the same manifest with one worker and multiple workers. Where available, also compare the Windows thread mode. Compare canonical sets rather than log order:

```text
(sample_id, member_path, verdict, score, sha256, evidence_groups, status)
```

The invariant is:

```text
scheduled = completed + skipped + unsupported + errors
```

Worker exceptions, queue loss, and timeout are terminal per-case records, not log-only events. The test fails on missing IDs, duplicates, score/evidence divergence, or unstable archive identity.

Archive fixtures cover traversal attempts, absolute member paths, duplicate names, nested archives, size/file/depth budgets, corrupt archives, unsupported extractors, and member-source mapping.

## Tests and verification

Add focused checks without replacing the current regression checks:

- `check_benchmark_manifest.py`: schema, labels, IDs, hashes, split leakage, fail-closed missing cases;
- `check_benchmark_metrics.py`: confusion counts, unknown handling, threshold sweep, intervals;
- `check_report_schema.py`: existing report names/order remain unchanged;
- `check_review_bundle_compat.py`: old bundle round trip plus optional benchmark member;
- `check_archive_benchmark.py`: stable member identity, budgets, traversal, source status;
- `check_parallel_equivalence.py`: worker-count equivalence and terminal-result invariant;
- `check_model_metadata.py`: class ordering, feature hash, mismatch rejection, no-model compatibility;
- existing `check_fp_guard.py`, `check_ast_df.py`, `check_scan_policy_defaults.py`, and `run-regression.py`.

The regression entrypoint must run all required checks and fail when a positive YARA case is no longer detected, a benign case is detected, an expected case is skipped, an error is counted as clean, a worker loses a result, an archive member cannot be identified, or the legacy report schema changes unexpectedly.

## Release gates

Fusion remains shadow-only until all of the following are true:

- the labeled manifest has no missing, duplicate, or hash-mismatched cases;
- the existing hash IOC behavior is unchanged;
- the test split is family-disjoint from train/calibration;
- recall and false-positive metrics are measured on the locked test split;
- the selected operating point is fixed before final test evaluation;
- quarantine precision does not decrease;
- archive and normal-file results map to stable candidate identities;
- one-worker and multi-worker results are equivalent;
- gray-only review bundles are accepted and retain source/evidence status;
- policy/model/rule provenance is present;
- all regression and compatibility checks pass.

If any gate fails, retain shadow mode and report the failing metric or invariant. No threshold is changed solely because a single sample looks noisy.

## Expected outcome

The first implementation produces an auditable benchmark and shadow evidence stream while preserving the current scanner decisions. Later releases can enable calibrated behavioral fusion and stricter gray-zone decisions using measured evidence rather than unverified threshold changes.
