#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Train an optional local AST-DF model from static sample files."""

import argparse
import hashlib
import json
import os
import pickle
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.ast_df import (
    ARTIFACT_VERSION,
    EXTRACTOR_VERSION,
    FEATURE_NAMES,
    _predict_probability,
    build_model_metadata,
    extract_features,
    feature_vector,
)

DOWNLOAD_TIMEOUT_SECONDS = 30
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ZIP_MEMBERS = 50000
MAX_ZIP_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 256 * 1024 * 1024

_SUPPORTED_EXT = {
    ".php", ".phtml", ".php5", ".php7", ".phar", ".inc",
    ".jsp", ".jspx",
    ".asp", ".aspx", ".ashx", ".asmx",
}


def _default_dataset_dir():
    return os.path.join(APP_ROOT, "dataset", "ast-df")


def _default_output():
    return os.path.join(APP_ROOT, "models", "ast_df.pkl")


def _safe_extract_zip(
    zip_path,
    target_dir,
    max_files=MAX_ZIP_MEMBERS,
    max_bytes=MAX_ZIP_UNCOMPRESSED_BYTES,
    max_member_bytes=MAX_ZIP_MEMBER_BYTES,
):
    if os.path.getsize(zip_path) > MAX_ARCHIVE_BYTES:
        raise SystemExit("ZIP archive exceeds size limit")
    with zipfile.ZipFile(zip_path) as archive:
        root = os.path.abspath(target_dir)
        members = archive.infolist()
        if len(members) > max_files:
            raise SystemExit("ZIP archive exceeds file-count limit")
        total_bytes = 0
        for member in members:
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
                raise SystemExit("unsafe zip member: %s" % member.filename)
            if member.file_size > max_member_bytes:
                raise SystemExit("ZIP member exceeds size limit: %s" % member.filename)
            total_bytes += member.file_size
            if total_bytes > max_bytes:
                raise SystemExit("ZIP archive exceeds uncompressed size limit")
            dest = os.path.abspath(os.path.join(target_dir, *name.split("/")))
            if dest != root and not dest.startswith(root + os.sep):
                raise SystemExit("unsafe zip member: %s" % member.filename)
        os.makedirs(target_dir, exist_ok=True)
        for member in members:
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            dest = os.path.abspath(os.path.join(target_dir, *name.split("/")))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with archive.open(member) as source, open(dest, "wb") as output:
                remaining = member.file_size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise SystemExit("truncated ZIP member: %s" % member.filename)
                    output.write(chunk)
                    remaining -= len(chunk)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redirect_target_is_allowed(url, allow_hosts, initial_scheme):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.scheme != initial_scheme:
        raise SystemExit("redirect scheme is not allowed: %s" % url)
    if parsed.hostname not in allow_hosts:
        raise SystemExit("redirect host not allowed: %s" % (parsed.hostname or ""))
    return parsed


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_hosts, initial_scheme):
        self.allow_hosts = set(allow_hosts)
        self.initial_scheme = initial_scheme

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _redirect_target_is_allowed(newurl, self.allow_hosts, self.initial_scheme)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def _select_calibration_threshold(scores_and_labels):
    candidates = sorted(set([0.5] + [score for score, _label in scores_and_labels]))
    return max(candidates, key=lambda value: (
        sum(score >= value and label == 1 for score, label in scores_and_labels),
        -sum(score >= value and label == 0 for score, label in scores_and_labels),
        value,
    ))

def _download_zip(url, allow_hosts, dataset_dir, sha256=None):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("download URL must use http/https: %s" % url)
    if parsed.hostname not in allow_hosts:
        raise SystemExit("host not allowed for download: %s" % (parsed.hostname or ""))
    if not parsed.path.lower().endswith(".zip"):
        raise SystemExit("only .zip dataset downloads are supported: %s" % url)
    if sha256 is not None and (len(sha256) != 64 or any(char not in "0123456789abcdefABCDEF" for char in sha256)):
        raise SystemExit("download SHA-256 must be a 64-character hex digest")

    downloads_dir = os.path.join(dataset_dir, "downloads")
    os.makedirs(downloads_dir, exist_ok=True)
    filename = os.path.basename(parsed.path) or "dataset.zip"
    zip_path = os.path.join(downloads_dir, filename)
    request = urllib.request.Request(url, headers={"User-Agent": "webshell-scan-training/1"})
    opener = urllib.request.build_opener(_AllowlistedRedirectHandler(allow_hosts, parsed.scheme))
    try:
        with opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response, open(zip_path, "wb") as output:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_ARCHIVE_BYTES:
                raise SystemExit("downloaded ZIP exceeds size limit")
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise SystemExit("downloaded ZIP exceeds size limit")
                output.write(chunk)
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit("dataset download failed: %s" % exc)
    if sha256:
        actual_sha256 = _sha256_file(zip_path)
        if actual_sha256.lower() != sha256.lower():
            raise SystemExit(
                "sha256 mismatch for %s: expected %s, got %s" % (url, sha256, actual_sha256))
    extract_dir = os.path.join(downloads_dir, os.path.splitext(filename)[0])
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)
    _safe_extract_zip(zip_path, extract_dir)
    return extract_dir


_SPLITS = ("train", "calibration", "test")


def _family_key(path, split_dir):
    relative = os.path.relpath(path, split_dir).split(os.sep)
    if len(relative) < 2:
        raise SystemExit("sample must be inside benign/ or webshell/: %s" % path)
    relative = relative[1:]
    return "/".join(relative[:-1]) if len(relative) > 1 else os.path.splitext(relative[0])[0].lower()


def _iter_split_samples(split_dir):
    for label_name, label in (("benign", 0), ("webshell", 1)):
        root = os.path.join(split_dir, label_name)
        if not os.path.isdir(root):
            raise SystemExit("missing dataset directory: %s" % root)
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in sorted(filenames):
                ext = os.path.splitext(filename)[1].lower()
                if ext in _SUPPORTED_EXT:
                    yield os.path.join(dirpath, filename), ext, label


def _dataset_hash(samples_by_split):
    digest = hashlib.sha256()
    for split in _SPLITS:
        split_dir = samples_by_split[split][0][4]
        for path, _ext, label, _features, _root in samples_by_split[split]:
            relative = os.path.relpath(path, split_dir).replace(os.sep, "/")
            with open(path, "rb") as handle:
                data = handle.read()
            digest.update(("%s\0%s\0%s\0%s\n" % (
                split, relative, label, hashlib.sha256(data).hexdigest())).encode("utf-8"))
    return digest.hexdigest()


def _load_split_rows(split_dir):
    rows = []
    labels = []
    counts = {0: 0, 1: 0}
    for path, ext, label in _iter_split_samples(split_dir):
        with open(path, "rb") as handle:
            data = handle.read()
        features = extract_features(data, ext, path, {})
        rows.append((path, ext, label, feature_vector(features)))
        labels.append(label)
        counts[label] += 1
    if len(set(labels)) != 2:
        raise SystemExit("each dataset split needs benign and webshell samples")
    return rows, counts


def _materialize_legacy_splits(dataset_dir, legacy_dirs):
    generated_root = os.path.join(dataset_dir, ".ast-df-generated-splits")
    if os.path.isdir(generated_root):
        shutil.rmtree(generated_root)
    split_dirs = {split: os.path.join(generated_root, split) for split in _SPLITS}
    for split_dir in split_dirs.values():
        for label in ("benign", "webshell"):
            os.makedirs(os.path.join(split_dir, label), exist_ok=True)

    for label in ("benign", "webshell"):
        root = legacy_dirs[label]
        grouped = {}
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in sorted(filenames):
                ext = os.path.splitext(filename)[1].lower()
                if ext not in _SUPPORTED_EXT:
                    continue
                path = os.path.join(dirpath, filename)
                relative = os.path.relpath(path, root).replace(os.sep, "/")
                parts = relative.split("/")
                family = "/".join(parts[:-1]) if len(parts) > 1 else os.path.splitext(parts[0])[0].lower()
                grouped.setdefault(family, []).append((path, relative))
        families = sorted(grouped)
        if len(families) < len(_SPLITS):
            raise SystemExit("legacy dataset needs at least three families per label")
        for index, family in enumerate(families):
            split_dir = split_dirs[_SPLITS[index % len(_SPLITS)]]
            for path, relative in grouped[family]:
                destination = os.path.join(split_dir, label, relative.replace("/", os.sep))
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                shutil.copy2(path, destination)
    return split_dirs

def _load_splits(dataset_dir):
    split_dirs = {split: os.path.join(dataset_dir, split) for split in _SPLITS}
    if not all(os.path.isdir(path) for path in split_dirs.values()):
        legacy = {label: os.path.join(dataset_dir, label) for label in ("benign", "webshell")}
        if not all(os.path.isdir(path) for path in legacy.values()):
            missing = next(path for path in split_dirs.values() if not os.path.isdir(path))
            raise SystemExit("missing dataset split directory: %s" % missing)
        split_dirs = _materialize_legacy_splits(dataset_dir, legacy)

    samples_by_split = {}
    family_splits = {}
    counts_by_split = {}
    for split in _SPLITS:
        split_dir = split_dirs[split]
        rows, counts = _load_split_rows(split_dir)
        samples_by_split[split] = [item + (split_dir,) for item in rows]
        counts_by_split[split] = counts
        for path, _ext, label, _vector, _root in samples_by_split[split]:
            family = _family_key(path, split_dir)
            family_key = (label, family)
            previous_split = family_splits.setdefault(family_key, split)
            if previous_split != split:
                raise SystemExit("dataset family appears in multiple splits: %s" % family)
    return samples_by_split, counts_by_split







def _new_model():
    try:
        from deepforest import CascadeForestClassifier
        return CascadeForestClassifier(random_state=42), "deepforest.CascadeForestClassifier"
    except Exception:
        pass
    try:
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(
            n_estimators=200, random_state=42, class_weight="balanced"), "sklearn.RandomForestClassifier"
    except Exception:
        raise SystemExit("install a training dependency first: deepforest or scikit-learn")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Train optional AST-DF model from dataset/ast-df/{train,calibration,test}/{benign,webshell}; legacy benign/webshell is split deterministically by family.")
    parser.add_argument("--dataset-dir", default=_default_dataset_dir())
    parser.add_argument("--output", default=_default_output())
    parser.add_argument("--download-url", action="append", default=[])
    parser.add_argument("--download-sha256", action="append", default=[])
    parser.add_argument("--allow-host", action="append", default=[])
    args = parser.parse_args(argv)

    dataset_dir = os.path.abspath(args.dataset_dir)
    allow_hosts = set(args.allow_host)
    if args.download_sha256 and len(args.download_url) != len(args.download_sha256):
        raise SystemExit("each --download-url must have one matching --download-sha256")
    for index, url in enumerate(args.download_url):
        sha256 = args.download_sha256[index] if args.download_sha256 else None
        _download_zip(url, allow_hosts, dataset_dir, sha256)

    samples, counts = _load_splits(dataset_dir)
    rows = [item[3] for item in samples["train"]]
    labels = [item[2] for item in samples["train"]]
    model, model_name = _new_model()
    model.fit(rows, labels)

    calibration_pairs = [
        (_predict_probability(model, item[3]), item[2]) for item in samples["calibration"]]
    threshold = _select_calibration_threshold(calibration_pairs)

    test_scores = [_predict_probability(model, item[3]) for item in samples["test"]]
    test_labels = [item[2] for item in samples["test"]]
    predicted = [score >= threshold for score in test_scores]
    tp = sum(actual == 1 and guess for actual, guess in zip(test_labels, predicted))
    fp = sum(actual == 0 and guess for actual, guess in zip(test_labels, predicted))
    tn = sum(actual == 0 and not guess for actual, guess in zip(test_labels, predicted))
    fn = sum(actual == 1 and not guess for actual, guess in zip(test_labels, predicted))
    metrics = {
        "threshold": threshold,
        "test": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": float(tp) / (tp + fp) if tp + fp else 0.0,
        "recall": float(tp) / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": float(fp) / (fp + tn) if fp + tn else 0.0,
    }
    dataset_hash = _dataset_hash(samples)
    metadata = build_model_metadata(
        model, FEATURE_NAMES, EXTRACTOR_VERSION, dataset_hash, threshold)
    package = {
        "artifact_version": ARTIFACT_VERSION,
        "model": model,
        "metadata": metadata,
        "model_name": model_name,
        "metrics": metrics,
    }
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "wb") as handle:
        pickle.dump(package, handle, protocol=pickle.HIGHEST_PROTOCOL)

    print("dataset: %s" % json.dumps(counts, sort_keys=True))
    print("trained %s with %d features" % (model_name, len(FEATURE_NAMES)))
    print("locked calibration threshold: %.4f" % threshold)
    print("test metrics: %s" % json.dumps(metrics, sort_keys=True))
    print("wrote %s" % output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
