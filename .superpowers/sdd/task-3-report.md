# Task 3 report

- Scope: policy validation and shadow defaults only.
- Implemented `validate_scan_policy` with known-key filtering, strict booleans, non-negative integer caps/thresholds, bounded ratios/probabilities, and list validation.
- Implemented canonical sorted-key JSON `policy_sha256`.
- `load_scan_policy` now returns validated defaults when config is absent and falls back to validated defaults on invalid/unreadable config.
- Added aligned shadow defaults to `config/scan-policy.json` and `DEFAULT_POLICY`; fusion remains disabled.
- No detector or fusion runtime behavior was changed. No secrets were added.

Checks:
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_policy_validation.py` — PASS
- `PYTHONPATH=webshell-scan-docker python webshell-scan-docker/tests/check_scan_policy_defaults.py` — PASS
- `python -m py_compile webshell-scan-docker/libs/scan_policy.py webshell-scan-docker/tests/check_policy_validation.py webshell-scan-docker/tests/check_scan_policy_defaults.py` — PASS
- `git diff --check` — PASS

Concerns: invalid configured values are rejected for the whole config and safely fall back to validated defaults, preserving the existing loader fallback behavior.
