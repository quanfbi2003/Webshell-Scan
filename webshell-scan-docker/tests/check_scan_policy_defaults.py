#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check config/scan-policy.json stays aligned with DEFAULT_POLICY."""

import json
import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.scan_policy import DEFAULT_POLICY, validate_scan_policy


EXPECTED_SHADOW_DEFAULTS = {
    "shadow_mode": True,
    "behavioral_fusion_enabled": False,
    "behavioral_corroboration_ratio": 0.25,
    "behavioral_fusion_cap": 100,
    "quarantine_requires_confirmed": True,
}


with open(os.path.join(APP_ROOT, "config", "scan-policy.json"), "r", encoding="utf-8") as handle:
    config_policy = json.load(handle)

missing = sorted(set(config_policy) - set(DEFAULT_POLICY))
extra = sorted(set(DEFAULT_POLICY) - set(config_policy))
changed = sorted(
    key for key in set(config_policy) & set(DEFAULT_POLICY)
    if config_policy[key] != DEFAULT_POLICY[key]
)

assert not missing, "missing DEFAULT_POLICY keys: %s" % missing
assert not extra, "extra DEFAULT_POLICY keys: %s" % extra
assert not changed, "different defaults: %s" % changed
assert all(DEFAULT_POLICY[key] == value for key, value in EXPECTED_SHADOW_DEFAULTS.items())
assert validate_scan_policy(config_policy) == validate_scan_policy(DEFAULT_POLICY)
print("scan policy defaults aligned")
