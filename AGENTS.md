# AGENTS.md

## Repository Scope

This repository contains a Python-based webshell scanner with YARA, hash IOC, SSDeep, entropy, archive extraction, VirusTotal support, and static deobfuscation layers.

Primary code lives under `webshell-scan-docker/`. The `webshell-scan-upgrader/` tree is related tooling and signature material; avoid changing both trees for one fix unless the request explicitly needs it.

## Working Rules

- Prefer narrow, behavior-preserving edits. Do not refactor scanner flow, policy defaults, or signature databases unless that is required for the task.
- Treat quarantined samples, decoded classes, and webshell artifacts as hostile data. Analyze statically; do not execute samples or dynamically load decoded payload classes.
- Use `rg` for searches and inspect existing patterns before adding new YARA rules or heuristics.
- Keep custom detection logic in `webshell-scan-docker/libs/signature-base/custom/` when possible.
- Keep policy defaults in `webshell-scan-docker/config/scan-policy.json` and `webshell-scan-docker/libs/scan_policy.py` aligned when changing default behavior.
- On Windows, set `PYTHONIOENCODING=utf-8` before running commands that print Vietnamese text.
- Do not delete quarantine, logs, decoded samples, or generated reports unless the user explicitly asks.

## Verification

Use the smallest verification that covers the change:

Run these from the repository root:

- Python syntax check:
  `python -B -c "import pathlib; [compile(p.read_text(encoding='utf-8'), str(p), 'exec') for p in map(pathlib.Path, ['webshell-scan-docker/webshell-scan.py', 'webshell-scan-docker/libs/deobfuscate.py']) if p.exists()]"`
- Custom YARA compile:
  `python -B -c "import yara; yara.compile(filepath=r'webshell-scan-docker\\libs\\signature-base\\custom\\yara_java_memshell.yar'); print('yara compile ok')"`

Run these from `webshell-scan-docker/`:

- Health check:
  `python webshell-scan.py --health-check -p .`
- Regression samples:
  `python tests/run-regression.py`
- Single-file scan:
  `python webshell-scan.py -p <file> --min-score 40`

## Reporting

When reporting scanner changes, include:

- The detection or behavior added.
- The rule, heuristic, or policy file changed.
- The exact validation command and whether it passed.
- Any known blind spots, especially for encoded Java/JSP memory-shell variants.
