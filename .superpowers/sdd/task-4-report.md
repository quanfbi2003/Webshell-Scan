# Task 4 report

- Scope: AST-DF artifact metadata, positive-class inference, explicit training splits/calibration, and safe explicit ZIP handling.
- Added versioned local artifact metadata with feature ordering/hash, extractor version, dataset/model hashes, positive label, locked threshold, and optional language compatibility.
- Inference now resolves probabilities through `classes_`, rejects malformed/incompatible artifacts with `(0, "model_incompatible")`, and preserves `(0, None)` for missing models.
- Training now requires family-disjoint `train`, `calibration`, and `test` directories, selects/locks threshold from calibration, evaluates test metrics, and writes metadata plus metrics in the artifact envelope.
- Explicit ZIP downloads use HTTP(S) allowlisting, timeout, archive/member/file-byte limits, traversal-safe member validation, streaming extraction, and optional SHA-256 verification. Samples are never executed or imported; ML dependencies remain training-only.

Checks:
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_ast_df.py` — PASS
- `python -m py_compile webshell-scan-docker/libs/ast_df.py webshell-scan-docker/tools/train-ast-df.py` — PASS
- `python -m py_compile webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `python webshell-scan-docker/tools/train-ast-df.py --help` — PASS
- `git diff --check` — PASS

Concerns: no real dataset was downloaded or trained, per scope; the training command now intentionally fails closed when split directories are absent. No runtime dependencies or secrets were added.

Review fixes:
- Redirects are checked on every HTTP redirect and must retain the initial scheme and an explicitly allowlisted host.
- Removed the arbitrary `--threshold` override; artifact thresholds are always selected from calibration scores and locked before test metrics.
- Non-list/non-tuple feature metadata now returns `(0, "model_incompatible")`; missing model remains `(0, None)`.
- Existing legacy `benign/webshell` datasets are supported through deterministic family-based materialization into train/calibration/test splits; the help text documents this behavior.
- Removed duplicate FakeModel attributes and kept no unused legacy loader helpers.

Review regression/results:
- Redirect allowlist and scheme checks — PASS
- Arbitrary CLI threshold cannot become artifact threshold — PASS
- Malformed feature metadata explicit incompatible status — PASS
- Legacy layout support path and split documentation — PASS (no real training executed)
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_ast_df.py` — PASS
- `python -m py_compile webshell-scan-docker/libs/ast_df.py webshell-scan-docker/tools/train-ast-df.py webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `python webshell-scan-docker/tools/train-ast-df.py --help` — PASS
- `git diff --check` — PASS

No downloads, samples, real training, or secrets used.
This review fix was committed separately from the original task commit.

Re-review fix:
- Legacy family leakage validation now keys family identity by `(label, family)`, allowing benign/webshell to share names while still rejecting a same-label family crossing splits.
- Added a temporary regression fixture with shared benign/webshell families `a`, `b`, and `c`; `_load_splits` succeeds and verifies no same-label family leakage.

Re-review results:
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_ast_df.py` — PASS
- `python -m py_compile webshell-scan-docker/libs/ast_df.py webshell-scan-docker/tools/train-ast-df.py webshell-scan-docker/tests/check_model_metadata.py` — PASS
- `python webshell-scan-docker/tools/train-ast-df.py --help` — PASS
- `git diff --check` — PASS

No downloads, samples, real training, or secrets used.
This re-review fix was committed separately.
