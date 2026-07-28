#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Focused checks for scan-policy validation and reproducible hashing."""

import json
import os
import sys
import tempfile

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.scan_policy import DEFAULT_POLICY, load_scan_policy, policy_sha256, validate_scan_policy


EXPECTED_SHADOW_DEFAULTS = {
    "shadow_mode": True,
    "behavioral_fusion_enabled": False,
    "behavioral_corroboration_ratio": 0.25,
    "behavioral_fusion_cap": 100,
    "quarantine_requires_confirmed": True,
}


validated_defaults = validate_scan_policy(DEFAULT_POLICY)
assert all(validated_defaults[key] == value for key, value in EXPECTED_SHADOW_DEFAULTS.items())

for invalid_ratio in (-0.1, 1.1):
    try:
        validate_scan_policy(dict(DEFAULT_POLICY, behavioral_corroboration_ratio=invalid_ratio))
    except ValueError:
        pass
    else:
        raise AssertionError("ratio %s was accepted" % invalid_ratio)

try:
    validate_scan_policy(dict(DEFAULT_POLICY, behavioral_fusion_cap=100.5))
except ValueError:
    pass
else:
    raise AssertionError("non-integer score cap was accepted")

filtered = validate_scan_policy(dict(DEFAULT_POLICY, behavioral_unknown_key=True))
assert "behavioral_unknown_key" not in filtered

with tempfile.TemporaryDirectory() as temp_dir:
    loaded = load_scan_policy(temp_dir)
assert loaded == validate_scan_policy(DEFAULT_POLICY)

assert policy_sha256({"b": 2, "a": 1}) == policy_sha256({"a": 1, "b": 2})

config_path = os.path.join(APP_ROOT, "config", "scan-policy.json")
with open(config_path, "r", encoding="utf-8") as handle:
    config_policy = json.load(handle)
assert validate_scan_policy(config_policy) == validate_scan_policy(DEFAULT_POLICY)

print("policy validation checks passed")
