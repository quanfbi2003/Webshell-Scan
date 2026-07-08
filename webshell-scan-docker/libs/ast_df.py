# -*- coding: utf-8 -*-
"""AST-DF-style static feature extraction and local model scoring."""

import os
import pickle
import re

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
    cached = _MODEL_CACHE.get(path)
    if cached is not None:
        return cached
    with open(path, "rb") as handle:
        model = pickle.load(handle)
    _MODEL_CACHE[path] = model
    return model


def _unwrap_model(model):
    if isinstance(model, dict) and "model" in model:
        feature_names = tuple(model.get("feature_names", ()))
        if feature_names and feature_names != FEATURE_NAMES:
            raise ValueError("AST-DF model feature_names mismatch")
        return model["model"]
    return model


def _predict_probability(model, vector):
    model = _unwrap_model(model)
    rows = [vector]
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(rows)
        first = proba[0]
        if hasattr(first, "__len__") and len(first) > 1:
            return float(first[1])
        return float(first[0])
    prediction = model.predict(rows)[0]
    return float(prediction)


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
        probability = _predict_probability(_load_model(model_path), feature_vector(features))
    except Exception:
        return 0, None

    threshold = float(policy.get("ast_df_min_probability", 0.70))
    if probability < threshold:
        return 0, None

    cap = int(policy.get("ast_df_score_cap", 90) or 90)
    score = int(round(min(cap, max(1, probability * cap))))
    return score, "AST-DF model probability %.2f (static AST-like features)" % probability
