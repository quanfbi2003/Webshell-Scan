# AST-DF webshell detection design

## Goal

Add an AST-DF-style detection layer to the existing scanner without breaking the current YARA/IOC/SSDeep/heuristic flow.

The scanner must remain usable when no AST-DF model exists. Dataset download and model training must be explicit tooling, not something the scanner does during a scan.

## Approach

Use three small pieces:

1. `libs/ast_df.py`
   - Static feature extraction for PHP/JSP/ASP-like files.
   - Build a lightweight AST-like token tree using stdlib-only parsing/regex.
   - Extract numeric features for source, sink, decode, dynamic dispatch, file operations, network operations, auth channel, obfuscation density, depth, branching, file size, and platform.
   - Load a local model only when configured and present.
   - Score a file as `(subscore, reason)` for the scanner.

2. Scanner integration in `webshell-scan.py`
   - Import AST-DF helpers.
   - Run AST-DF after existing static heuristics.
   - Add evidence group `ast_df` when the local model predicts webshell probability above policy threshold.
   - Cap score with `ast_df_score_cap`.
   - If the model/dependency is missing, return no score and keep existing scan behavior.

3. `tools/train-ast-df.py`
   - Optional offline training command.
   - Accept local dataset directories and optional allowlisted download URLs.
   - Expected normalized dataset layout:
     - `dataset/ast-df/webshell/`
     - `dataset/ast-df/benign/`
   - Extract feature rows using `libs.ast_df`.
   - Train with an available Deep Forest implementation when installed; otherwise use an installed sklearn tree ensemble fallback.
   - Save model to `models/ast_df.pkl`.
   - Fail clearly if dependencies or dataset are missing.

## Policy

Add defaults to both policy locations:

- `ast_df_enabled`: true
- `ast_df_model_path`: `models/ast_df.pkl`
- `ast_df_min_probability`: `0.70`
- `ast_df_score_cap`: `90`
- `ast_df_max_file_bytes`: `2097152`

## Data and safety

- Do not execute samples.
- Do not auto-download during scan.
- Downloads are explicit in the train tool only.
- Unknown external datasets are not committed to the repo.
- Model loading is local-path only.

## Testing

Add a small assert-based check for:

- feature extraction on a PHP webshell-like sample,
- benign PHP producing lower suspicious feature counts,
- scoring returning `(0, None)` when no model is present.

Then run:

- Python syntax compile for changed Python files.
- Existing regression test if local dependencies allow it.

## Known limits

This is an AST-DF-compatible integration path, not a guaranteed reproduction of the paper until a vetted dataset and Deep Forest implementation are provided. The first implementation gives the scanner a stable AST-DF feature/model slot and an offline training path.
