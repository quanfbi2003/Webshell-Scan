#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Train an optional local AST-DF model from static sample files."""

import argparse
import hashlib
import os
import pickle
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.ast_df import FEATURE_NAMES, extract_features, feature_vector

_SUPPORTED_EXT = {
    ".php", ".phtml", ".php5", ".php7", ".phar", ".inc",
    ".jsp", ".jspx",
    ".asp", ".aspx", ".ashx", ".asmx",
}


def _default_dataset_dir():
    return os.path.join(APP_ROOT, "dataset", "ast-df")


def _default_output():
    return os.path.join(APP_ROOT, "models", "ast_df.pkl")


def _safe_extract_zip(zip_path, target_dir):
    with zipfile.ZipFile(zip_path) as archive:
        root = os.path.abspath(target_dir)
        for member in archive.infolist():
            dest = os.path.abspath(os.path.join(target_dir, member.filename))
            if dest != root and not dest.startswith(root + os.sep):
                raise SystemExit("unsafe zip member: %s" % member.filename)
        archive.extractall(target_dir)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_zip(url, allow_hosts, dataset_dir, sha256):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("download URL must use http/https: %s" % url)
    if parsed.hostname not in allow_hosts:
        raise SystemExit("host not allowed for download: %s" % (parsed.hostname or ""))
    if not parsed.path.lower().endswith(".zip"):
        raise SystemExit("only .zip dataset downloads are supported: %s" % url)

    downloads_dir = os.path.join(dataset_dir, "downloads")
    os.makedirs(downloads_dir, exist_ok=True)
    filename = os.path.basename(parsed.path) or "dataset.zip"
    zip_path = os.path.join(downloads_dir, filename)
    urllib.request.urlretrieve(url, zip_path)
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


def _iter_samples(dataset_dir):
    for label_name, label in (("benign", 0), ("webshell", 1)):
        root = os.path.join(dataset_dir, label_name)
        if not os.path.isdir(root):
            raise SystemExit("missing dataset directory: %s" % root)
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext in _SUPPORTED_EXT:
                    yield os.path.join(dirpath, filename), ext, label


def _load_rows(dataset_dir):
    rows = []
    labels = []
    counts = {0: 0, 1: 0}
    for path, ext, label in _iter_samples(dataset_dir):
        with open(path, "rb") as handle:
            data = handle.read()
        features = extract_features(data, ext, path, {})
        rows.append(feature_vector(features))
        labels.append(label)
        counts[label] += 1
    if len(set(labels)) != 2:
        raise SystemExit("dataset needs at least one benign and one webshell sample")
    return rows, labels, counts


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
        description="Train optional AST-DF model from dataset/ast-df/{benign,webshell}.")
    parser.add_argument("--dataset-dir", default=_default_dataset_dir())
    parser.add_argument("--output", default=_default_output())
    parser.add_argument("--download-url", action="append", default=[])
    parser.add_argument("--download-sha256", action="append", default=[])
    parser.add_argument("--allow-host", action="append", default=[])
    args = parser.parse_args(argv)

    dataset_dir = os.path.abspath(args.dataset_dir)
    allow_hosts = set(args.allow_host)
    if len(args.download_url) != len(args.download_sha256):
        raise SystemExit("each --download-url must have one matching --download-sha256")
    for url, sha256 in zip(args.download_url, args.download_sha256):
        _download_zip(url, allow_hosts, dataset_dir, sha256)

    rows, labels, counts = _load_rows(dataset_dir)
    model, model_name = _new_model()
    model.fit(rows, labels)

    package = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "model_name": model_name,
    }
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "wb") as handle:
        pickle.dump(package, handle, protocol=pickle.HIGHEST_PROTOCOL)

    print("dataset: %d benign, %d webshell" % (counts[0], counts[1]))
    print("trained %s with %d features on %d samples" % (model_name, len(FEATURE_NAMES), len(labels)))
    print("wrote %s" % output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
