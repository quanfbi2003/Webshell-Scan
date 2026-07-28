# -*- coding: utf-8 -*-
"""AST-DF-style static feature extraction and local model scoring."""

import os
import pickle
import re

import hashlib
import json
import math

_SUPPORTED_EXT = {
    ".php", ".phtml", ".php5", ".php7", ".phar", ".inc",
    ".jsp", ".jspx",
    ".asp", ".aspx", ".ashx", ".asmx",
}
_PHP_EXT = {".php", ".phtml", ".php5", ".php7", ".phar", ".inc"}
_JSP_EXT = {".jsp", ".jspx"}
_ASPNET_EXT = {".asp", ".aspx", ".ashx", ".asmx"}

_TOKEN_RE = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|->|::|==|!=|<=|>=|[{}()\[\];.,+\-*/=]"
)
_STRING_RE = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1", re.S)

_PATTERNS = {
    "source_count": (
        r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[|"
        r"\$HTTP_(?:GET|POST|COOKIE|SERVER|POST_FILES)_VARS\s*\[|"
        r"php://input|filter_input\s*\(|getallheaders\s*\(|apache_request_headers\s*\(|"
        r"request\.(?:getParameter|getHeader|getInputStream|getReader)\s*\(|"
        r"Request\.(?:Form|QueryString|Cookies|ServerVariables|Files)\b|Request\s*\["
    ),
    "sink_count": (
        r"\b(?:eval|assert|system|shell_exec|passthru|proc_open|popen|exec)\s*\(|"
        r"['\"]sys['\"]\s*\.\s*['\"]tem['\"]|"
        r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|new\s+ProcessBuilder\s*\(|"
        r"ScriptEngineManager|\.eval\s*\(|Server\.CreateObject\s*\(|WScript\.Shell|Process\.Start\s*\("
    ),
    "decode_count": (
        r"\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|rawurldecode|"
        r"convert_uudecode|openssl_decrypt)\s*\(|"
        r"Base64\.getDecoder\s*\(|sun\.misc\.BASE64Decoder|Convert\.FromBase64String\s*\(|\batob\s*\("
    ),
    "dynamic_dispatch_count": (
        r"\$[A-Za-z_][A-Za-z0-9_]*\s*\(|\$\{[^}]+\}\s*\(|"
        r"\b(?:call_user_func|call_user_func_array|create_function)\s*\(|"
        r"Reflection(?:Class|Method)|\.invoke\s*\("
    ),
    "file_ops_count": (
        r"\b(?:file_put_contents|file_get_contents|fopen|fwrite|unlink|copy|rename|chmod|chown|"
        r"move_uploaded_file|readfile|include|require|include_once|require_once)\s*\(|"
        r"new\s+File(?:Input|Output)Stream\s*\(|File\.WriteAll"
    ),
    "network_count": (
        r"\b(?:fsockopen|pfsockopen|curl_exec|curl_setopt|socket_create|socket_connect)\s*\(|"
        r"new\s+Socket\s*\(|HttpURLConnection|WebClient|TcpClient"
    ),
    "auth_channel_count": r"\b(?:password|passwd|pwd|auth|token|cookie|session|login|cmd)\b",
}

FEATURE_NAMES = (
    "file_size",
    "line_count",
    "token_count",
    "max_depth",
    "branch_count",
    "source_count",
    "sink_count",
    "decode_count",
    "dynamic_dispatch_count",
    "file_ops_count",
    "network_count",
    "auth_channel_count",
    "long_string_count",
    "string_concat_count",
    "variable_variable_count",
    "non_alnum_ratio",
    "suspicious_score",
    "is_php",
    "is_jsp",
    "is_aspnet",
)

EXTRACTOR_VERSION = "ast-df-features-v1"
ARTIFACT_VERSION = 1


def _feature_hash(feature_names):
    payload = json.dumps(list(feature_names), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_model_metadata(model, feature_names, extractor_version, dataset_hash, threshold, language=None):
    names = tuple(feature_names)
    if names != FEATURE_NAMES:
        raise ValueError("AST-DF model feature_names mismatch")
    if not isinstance(extractor_version, str) or not extractor_version:
        raise ValueError("AST-DF extractor_version is required")
    if not isinstance(dataset_hash, str) or not dataset_hash:
        raise ValueError("AST-DF dataset_hash is required")
    threshold = float(threshold)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("AST-DF threshold must be between 0 and 1")
    classes = getattr(model, "classes_", None)
    if classes is not None and 1 not in list(classes):
        raise ValueError("AST-DF model has no positive class")
    if language is not None and (not isinstance(language, str) or not language):
        raise ValueError("AST-DF language must be a non-empty string")
    model_hash = hashlib.sha256(pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)).hexdigest()
    return {
        "feature_names": list(names),
        "feature_hash": _feature_hash(names),
        "extractor_version": extractor_version,
        "dataset_hash": dataset_hash,
        "model_sha256": model_hash,
        "positive_label": 1,
        "threshold": threshold,
        "language": language,
    }


def _language_for_extension(extension):
    if extension in _PHP_EXT:
        return "php"
    if extension in _JSP_EXT:
        return "jsp"
    if extension in _ASPNET_EXT:
        return "aspnet"
    return None


def _validate_artifact(artifact, extension):
    if not isinstance(artifact, dict) or artifact.get("artifact_version") != ARTIFACT_VERSION:
        raise ValueError("AST-DF artifact version is unsupported")
    model = artifact.get("model")
    metadata = artifact.get("metadata")
    if model is None or not isinstance(metadata, dict):
        raise ValueError("AST-DF artifact metadata is missing")
    names = metadata.get("feature_names")
    if tuple(names or ()) != FEATURE_NAMES:
        raise ValueError("AST-DF model feature_names mismatch")
    if metadata.get("feature_hash") != _feature_hash(FEATURE_NAMES):
        raise ValueError("AST-DF model feature_hash mismatch")
    if metadata.get("extractor_version") != EXTRACTOR_VERSION:
        raise ValueError("AST-DF extractor_version mismatch")
    if not isinstance(metadata.get("dataset_hash"), str) or not metadata["dataset_hash"]:
        raise ValueError("AST-DF dataset_hash is missing")
    expected_model_hash = metadata.get("model_sha256")
    if not isinstance(expected_model_hash, str) or len(expected_model_hash) != 64:
        raise ValueError("AST-DF model hash is missing")
    actual_model_hash = hashlib.sha256(pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)).hexdigest()
    if expected_model_hash != actual_model_hash:
        raise ValueError("AST-DF model hash mismatch")
    if metadata.get("positive_label") != 1:
        raise ValueError("AST-DF positive_label is unsupported")
    try:
        threshold = float(metadata["threshold"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("AST-DF threshold is missing")
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("AST-DF threshold is invalid")
    language = metadata.get("language")
    if language is not None and language != _language_for_extension(extension):
        raise ValueError("AST-DF artifact language is unsupported")
    classes = getattr(model, "classes_", None)
    try:
        valid_classes = set(classes) == {0, 1} and len(classes) == 2
    except (TypeError, ValueError):
        valid_classes = False
    if not valid_classes:
        raise ValueError("AST-DF model class ordering is unknown")
    return model, threshold


_MODEL_CACHE = {}


def _decode_text(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding, errors="replace")
        except Exception:
            continue
    return ""


def _normalize_extension(extension, file_path=""):
    ext = (extension or os.path.splitext(file_path or "")[1] or "").lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    return ext


def _count(pattern, text):
    return len(re.findall(pattern, text, re.I | re.S))


def _max_depth(text):
    depth = 0
    max_seen = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closes = set(pairs.values())
    for char in text:
        if char in pairs:
            depth += 1
            if depth > max_seen:
                max_seen = depth
        elif char in closes and depth > 0:
            depth -= 1
    return max_seen


def extract_features(file_data, extension, file_path="", policy=None):
    """Extract stdlib-only AST-DF-style numeric features from source bytes."""
    text = _decode_text(file_data)
    ext = _normalize_extension(extension, file_path)
    tokens = _TOKEN_RE.findall(text)
    size = len(file_data) if hasattr(file_data, "__len__") else len(text)
    alnum = sum(1 for char in text if char.isalnum())
    non_alnum_ratio = 0.0
    if text:
        non_alnum_ratio = float(len(text) - alnum) / float(len(text))

    features = {
        "file_size": float(size),
        "line_count": float(text.count("\n") + 1 if text else 0),
        "token_count": float(len(tokens)),
        "max_depth": float(_max_depth(text)),
        "branch_count": float(_count(r"\b(?:if|else|for|foreach|while|switch|case|catch|try)\b", text)),
        "long_string_count": float(sum(1 for match in _STRING_RE.finditer(text) if len(match.group(0)) >= 80)),
        "string_concat_count": float(_count(r"['\"]\s*\.\s*['\"]|\$[A-Za-z_][A-Za-z0-9_]*\s*\.", text)),
        "variable_variable_count": float(_count(r"\$\$|\$\{", text)),
        "non_alnum_ratio": non_alnum_ratio,
        "is_php": 1.0 if ext in _PHP_EXT else 0.0,
        "is_jsp": 1.0 if ext in _JSP_EXT else 0.0,
        "is_aspnet": 1.0 if ext in _ASPNET_EXT else 0.0,
    }
    for name, pattern in _PATTERNS.items():
        features[name] = float(_count(pattern, text))

    features["suspicious_score"] = (
        features["source_count"] * 2.0 +
        features["sink_count"] * 3.0 +
        features["decode_count"] * 2.0 +
        features["dynamic_dispatch_count"] * 2.0 +
        features["file_ops_count"] +
        features["network_count"] +
        features["auth_channel_count"] * 0.5 +
        features["long_string_count"] +
        features["string_concat_count"] +
        features["variable_variable_count"] * 2.0
    )
    return features


def feature_vector(features):
    """Return model input values in stable training/inference order."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def _model_path(path, app_path):
    path = path or ""
    if "://" in path:
        return ""
    if not os.path.isabs(path):
        path = os.path.join(app_path or os.getcwd(), path)
    return os.path.abspath(path)


def _load_model(path):
    stat = os.stat(path)
    cache_key = (stat.st_mtime_ns, stat.st_size)
    cached = _MODEL_CACHE.get(path)
    if cached is not None and cached[0] == cache_key:
        return cached[1]
    with open(path, "rb") as handle:
        model = pickle.load(handle)
    _MODEL_CACHE[path] = (cache_key, model)
    return model


def _unwrap_model(model):
    if isinstance(model, dict) and "model" in model:
        feature_names = tuple(model.get("feature_names", ()))
        if feature_names and feature_names != FEATURE_NAMES:
            raise ValueError("AST-DF model feature_names mismatch")
        return model["model"]
    return model


def _predict_probability(model, vector, positive_label=1):
    model = _unwrap_model(model)
    rows = [vector]
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(rows)
        first = proba[0]
        if not hasattr(first, "__len__"):
            return float(first)
        classes = getattr(model, "classes_", None)
        if classes is None:
            if len(first) == 1:
                return float(first[0])
            raise ValueError("AST-DF model class ordering is unknown")
        try:
            index = list(classes).index(positive_label)
        except ValueError:
            raise ValueError("AST-DF model positive class is missing")
        if index >= len(first):
            raise ValueError("AST-DF model probability shape is invalid")
        return float(first[index])
    prediction = model.predict(rows)[0]
    return float(prediction == positive_label)


def ast_df_heuristic(file_data, extension, file_path, policy, app_path=None):
    """Score a file with a trusted local AST-DF model when one is configured."""
    if not policy or not policy.get("ast_df_enabled", True):
        return 0, None

    ext = _normalize_extension(extension, file_path)
    if ext not in _SUPPORTED_EXT:
        return 0, None

    max_bytes = int(policy.get("ast_df_max_file_bytes", 2 * 1024 * 1024) or 0)
    if max_bytes and hasattr(file_data, "__len__") and len(file_data) > max_bytes:
        return 0, None

    model_path = _model_path(policy.get("ast_df_model_path", "models/ast_df.pkl"), app_path)
    if not model_path or not os.path.isfile(model_path):
        return 0, None

    try:
        features = extract_features(file_data, ext, file_path, policy)
        artifact = _load_model(model_path)
        model, threshold = _validate_artifact(artifact, ext)
        probability = _predict_probability(model, feature_vector(features))
    except ValueError:
        return 0, "model_incompatible"
    except Exception:
        return 0, None

    if probability < threshold:
        return 0, None

    cap = int(policy.get("ast_df_score_cap", 90) or 90)
    score = int(round(min(cap, max(1, probability * cap))))
    return score, "AST-DF model probability %.2f (static AST-like features)" % probability
