# -*- coding: utf-8 -*-
"""Load scan policy from config/scan-policy.json."""

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
}


def load_scan_policy(app_path, logger=None):
    """Merge config/scan-policy.json over defaults."""
    policy = dict(DEFAULT_POLICY)
    config_path = os.path.join(app_path, "config", "scan-policy.json")
    if not os.path.isfile(config_path):
        if logger:
            logger.log("NOTICE", "Init", "Using default scan policy (no %s)" % config_path)
        return policy
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            user_policy = json.load(handle)
        if isinstance(user_policy, dict):
            policy.update(user_policy)
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
