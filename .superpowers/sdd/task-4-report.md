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
