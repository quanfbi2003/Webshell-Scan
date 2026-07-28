# -*- coding: utf-8 -*-
"""Self-checks for AST-DF artifact compatibility and probability semantics."""

import importlib.util
import io
import os
import pickle
import sys
import tempfile
import zipfile

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.ast_df import (  # noqa: E402
    EXTRACTOR_VERSION,
    FEATURE_NAMES,
    _predict_probability,
    ast_df_heuristic,
    build_model_metadata,
)

TRAIN_TOOL = os.path.join(APP_ROOT, "tools", "train-ast-df.py")
_SPEC = importlib.util.spec_from_file_location("train_ast_df", TRAIN_TOOL)
TRAIN = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(TRAIN)


def _zip_bytes(*members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return stream.getvalue()


with tempfile.TemporaryDirectory() as temp_dir:
    unsafe = os.path.join(temp_dir, "unsafe.zip")
    with open(unsafe, "wb") as handle:
        handle.write(_zip_bytes(("../escape.txt", b"no")))
    try:
        TRAIN._safe_extract_zip(unsafe, os.path.join(temp_dir, "out"))
    except SystemExit:
        pass
    else:
        raise AssertionError("unsafe ZIP member must be rejected")

    huge = os.path.join(temp_dir, "huge.zip")
    with open(huge, "wb") as handle:
        handle.write(_zip_bytes(("sample.php", b"x")))
    try:
        TRAIN._safe_extract_zip(huge, os.path.join(temp_dir, "out"), max_files=0)
    except SystemExit:
        pass
    else:
        raise AssertionError("ZIP limits must be enforced")


class FakeModel:
    classes_ = [1, 0]

    def predict_proba(self, rows):
        return [[0.9, 0.1] for _row in rows]


    classes_ = [1, 0]

    def predict_proba(self, rows):
        return [[0.9, 0.1] for _row in rows]


assert _predict_probability(FakeModel(), [0.0] * len(FEATURE_NAMES)) == 0.9

with tempfile.TemporaryDirectory() as temp_dir:
    model_path = os.path.join(temp_dir, "ast_df.pkl")
    metadata = build_model_metadata(
        FakeModel(), FEATURE_NAMES, EXTRACTOR_VERSION, "a" * 64, 0.70, language="php")
    assert len(metadata["model_sha256"]) == 64
    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": metadata}, handle)

    policy = {
        "ast_df_enabled": True,
        "ast_df_model_path": model_path,
        "ast_df_min_probability": 0.70,
        "ast_df_score_cap": 90,
        "ast_df_max_file_bytes": 2097152,
    }
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert score > 0 and reason

    metadata["feature_hash"] = "b" * 64
    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": metadata}, handle)
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert (score, reason) == (0, "model_incompatible"), (score, reason)

    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": {}}, handle)
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert (score, reason) == (0, "model_incompatible"), (score, reason)

    missing_policy = dict(policy, ast_df_model_path=os.path.join(temp_dir, "missing.pkl"))
    assert ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", missing_policy) == (0, None)

print("model metadata checks passed")
