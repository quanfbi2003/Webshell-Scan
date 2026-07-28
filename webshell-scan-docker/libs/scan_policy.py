# -*- coding: utf-8 -*-
"""Load scan policy from config/scan-policy.json."""

import copy
import hashlib
import json
import os

DEFAULT_POLICY = {
    "min_score_default": 40,
    "paranoid_min_score": 25,
    "gray_zone_min_score": 25,
    "ssdeep_enabled": True,
    "ssdeep_threshold_default": 50,
    "ssdeep_threshold_paranoid": 40,
    "entropy_enabled": True,
    "entropy_threshold": 7.2,
    "entropy_subscore": 15,
    "entropy_score_cap": 25,
    "entropy_upload_only": True,
    "paranoid_entropy_boost": 10,
    "source_sink_base_subscore": 35,
    "source_sink_max_subscore": 75,
    "source_sink_score_cap": 75,
    "source_sink_paranoid_boost": 10,
    "source_sink_max_file_bytes": 2 * 1024 * 1024,
    "webshell_capability_enabled": True,
    "webshell_capability_min_subscore": 30,
    "webshell_capability_max_subscore": 85,
    "webshell_capability_score_cap": 85,
    "webshell_capability_paranoid_boost": 10,
    "webshell_capability_max_file_bytes": 2 * 1024 * 1024,
    "webshell_capability_java_compact_max_bytes": 32768,
    "single_evidence_gray_enabled": True,
    "library_fp_guard_enabled": True,
    "single_webshell_capability_main_min_score": 80,
    "single_behavior_graph_main_min_score": 85,
    "behavior_graph_enabled": True,
    "behavior_graph_min_subscore": 35,
    "behavior_graph_max_subscore": 90,
    "behavior_graph_score_cap": 90,
    "behavior_graph_paranoid_boost": 10,
    "behavior_graph_max_file_bytes": 5 * 1024 * 1024,
    "ast_df_enabled": True,
    "ast_df_model_path": "models/ast_df.pkl",
    "ast_df_min_probability": 0.70,
    "ast_df_score_cap": 90,
    "ast_df_max_file_bytes": 2 * 1024 * 1024,
    "filename_ioc_score_cap": 80,
    "yara_score_cap": 120,
    "ssdeep_score_cap": 100,
    "deobfuscate_enabled": True,
    "deobfuscate_max_depth": 3,
    "deobfuscate_max_output_bytes": 2 * 1024 * 1024,
    "deobfuscate_max_file_bytes": 5 * 1024 * 1024,
    "deobfuscate_extensions": [
        ".php", ".phtml", ".php5", ".php7", ".phar", ".inc", ".jsp", ".asp", ".aspx",
    ],
    "upload_path_patterns": [
        "upload", "uploads", "tmp", "temp", "cache", "files", "media", "attachment", "attachments",
    ],
    "yara_rule_mode": "all",
    "webshell_yara_file_patterns": [
        "webshell", "web_shell", "memshell", "regeorg", "php", "jsp", "aspx", "asp", "shell",
    ],
    "vt_ssdeep_enabled": False,
    "vt_max_file_bytes": 5 * 1024 * 1024,
    "vt_include_findings": True,
    "vt_include_gray_zone": True,
    "shadow_mode": True,
    "behavioral_fusion_enabled": False,
    "behavioral_corroboration_ratio": 0.25,
    "behavioral_fusion_cap": 100,
    "quarantine_requires_confirmed": True,
}


_BOOL_KEYS = {key for key, value in DEFAULT_POLICY.items() if isinstance(value, bool)}
_INT_KEYS = {
    key for key, value in DEFAULT_POLICY.items()
    if type(value) is int and key != "behavioral_corroboration_ratio"
}
_FLOAT_KEYS = {"entropy_threshold", "ast_df_min_probability", "behavioral_corroboration_ratio"}
_LIST_KEYS = {key for key, value in DEFAULT_POLICY.items() if isinstance(value, list)}


def validate_scan_policy(policy):
    """Return validated known policy values merged over safe defaults."""
    if not isinstance(policy, dict):
        raise ValueError("scan policy must be an object")

    validated = copy.deepcopy(DEFAULT_POLICY)
    for key, value in policy.items():
        if key not in DEFAULT_POLICY:
            continue
        if key in _BOOL_KEYS:
            valid = type(value) is bool
        elif key in _INT_KEYS:
            valid = type(value) is int and value >= 0
        elif key in _FLOAT_KEYS:
            valid = type(value) in (int, float) and not isinstance(value, bool)
        elif key in _LIST_KEYS:
            valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
        else:
            valid = type(value) is type(DEFAULT_POLICY[key])
        if not valid:
            raise ValueError("invalid scan policy value for %s" % key)
        if key in ("behavioral_corroboration_ratio", "ast_df_min_probability") and not 0 <= value <= 1:
            raise ValueError("%s must be between 0 and 1" % key)
        validated[key] = copy.deepcopy(value)
    return validated


def policy_sha256(policy):
    """Return the SHA-256 of a canonical JSON policy representation."""
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict")
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_scan_policy(app_path, logger=None):
    """Merge and validate config/scan-policy.json over defaults."""
    policy = validate_scan_policy(DEFAULT_POLICY)
    config_path = os.path.join(app_path, "config", "scan-policy.json")
    if not os.path.isfile(config_path):
        if logger:
            logger.log("NOTICE", "Init", "Using default scan policy (no %s)" % config_path)
        return policy
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            user_policy = json.load(handle)
        policy = validate_scan_policy(user_policy)
        if logger:
            logger.log("INFO", "Init", "Loaded scan policy from %s" % config_path)
    except Exception as exc:
        if logger:
            logger.log("WARNING", "Init", "Cannot load scan policy %s: %s" % (config_path, exc))
    return policy


def apply_cli_overrides(policy, args):
    """Apply --paranoid / --min-score to effective runtime policy."""
    effective = dict(policy)
    min_score = getattr(args, "min_score", None)
    if min_score is not None:
        effective["min_score_effective"] = int(min_score)
    else:
        effective["min_score_effective"] = int(policy.get("min_score_default", 40))

    if getattr(args, "paranoid", False):
        effective["min_score_effective"] = int(policy.get("paranoid_min_score", 25))
        effective["ssdeep_threshold_effective"] = int(policy.get("ssdeep_threshold_paranoid", 40))
        effective["entropy_enabled_effective"] = True
        effective["paranoid_mode"] = True
    else:
        effective["ssdeep_threshold_effective"] = int(policy.get("ssdeep_threshold_default", 50))
        effective["entropy_enabled_effective"] = bool(policy.get("entropy_enabled", True))
        effective["paranoid_mode"] = False

    effective["gray_zone_min_score"] = int(policy.get("gray_zone_min_score", 25))

    if getattr(args, "vt_ssdeep", False):
        effective["vt_ssdeep_enabled"] = True

    effective["ssdeep_enabled_effective"] = bool(policy.get("ssdeep_enabled", True))
    if getattr(args, "no_ssdeep", False):
        effective["ssdeep_enabled_effective"] = False

    return effective
