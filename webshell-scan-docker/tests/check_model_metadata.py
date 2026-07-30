# -*- coding: utf-8 -*-
"""Self-checks for AST-DF artifact compatibility and probability semantics."""

import contextlib
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
    _MODEL_CACHE,
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
    split_root = os.path.join(temp_dir, "explicit")
    for split in TRAIN._SPLITS:
        for label in ("benign", "webshell"):
            family_dir = os.path.join(split_root, split, label, split + "-family")
            os.makedirs(family_dir, exist_ok=True)
            with open(os.path.join(family_dir, "one.php"), "wb") as handle:
                handle.write(b"<?php echo 1;")
            if split == "train":
                with open(os.path.join(family_dir, "two.php"), "wb") as handle:
                    handle.write(b"<?php echo 2;")
    explicit_splits, _counts = TRAIN._load_splits(split_root)
    assert len(explicit_splits["train"]) == 4

    crossing_root = os.path.join(temp_dir, "crossing")
    for split in ("train", "calibration"):
        family_dir = os.path.join(crossing_root, split, "benign", "family")
        os.makedirs(family_dir, exist_ok=True)
        with open(os.path.join(family_dir, "sample.php"), "wb") as handle:
            handle.write(b"<?php echo 1;")
    for split in TRAIN._SPLITS:
        family_dir = os.path.join(crossing_root, split, "webshell", "other")
        os.makedirs(family_dir, exist_ok=True)
        with open(os.path.join(family_dir, "sample.php"), "wb") as handle:
            handle.write(b"<?php eval($_GET['x']);")
    try:
        TRAIN._load_splits(crossing_root)
    except SystemExit:
        pass
    else:
        raise AssertionError("same-label family crossing splits must be rejected")


with contextlib.redirect_stderr(io.StringIO()):
    try:
        TRAIN.main(["--threshold", "0.01"])
    except SystemExit as exc:
        assert exc.code != 0, "arbitrary CLI threshold must be rejected"
    else:
        raise AssertionError("arbitrary CLI threshold must not be accepted")


try:
    TRAIN._redirect_target_is_allowed("https://allowed.example/next.zip", {"allowed.example"}, "https")
except AttributeError:
    raise AssertionError("redirect validation helper is required")
try:
    TRAIN._redirect_target_is_allowed("https://evil.example/next.zip", {"allowed.example"}, "https")
except SystemExit:
    pass
else:
    raise AssertionError("redirect to unallowlisted host must be rejected")

try:
    TRAIN._select_calibration_threshold([(0.9, 1), (0.1, 0)])
except AttributeError:
    raise AssertionError("calibration threshold selector is required")


with tempfile.TemporaryDirectory() as temp_dir:
    legacy_root = os.path.join(temp_dir, "legacy")
    for label in ("benign", "webshell"):
        for family in ("a", "b", "c"):
            family_dir = os.path.join(legacy_root, label, family)
            os.makedirs(family_dir, exist_ok=True)
            with open(os.path.join(family_dir, "sample.php"), "wb") as handle:
                handle.write(b"<?php echo 1;")
    legacy_splits, _counts = TRAIN._load_splits(legacy_root)
    assert all(legacy_splits[split] for split in TRAIN._SPLITS)
    for label in (0, 1):
        seen = {}
        for split in TRAIN._SPLITS:
            for _path, _ext, row_label, _vector, _root in legacy_splits[split]:
                if row_label != label:
                    continue
                family = TRAIN._family_key(_path, legacy_splits[split][0][4])
                assert family not in seen, "same-label family leaked across splits"
                seen[family] = split

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

    _MODEL_CACHE.clear()
    metadata["feature_hash"] = "b" * 64
    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": metadata}, handle)
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert (score, reason) == (0, "model_incompatible"), (score, reason)

    _MODEL_CACHE.clear()
    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": {}}, handle)
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert (score, reason) == (0, "model_incompatible"), (score, reason)

    _MODEL_CACHE.clear()
    malformed = dict(metadata, feature_names=3)
    with open(model_path, "wb") as handle:
        pickle.dump({"artifact_version": 1, "model": FakeModel(), "metadata": malformed}, handle)
    score, reason = ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", policy)
    assert (score, reason) == (0, "model_incompatible"), (score, reason)

    missing_policy = dict(policy, ast_df_model_path=os.path.join(temp_dir, "missing.pkl"))
    assert ast_df_heuristic(b"<?php echo $_GET['x'];", ".php", "shell.php", missing_policy) == (0, None)

print("model metadata checks passed")
