#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check config/scan-policy.json stays aligned with DEFAULT_POLICY."""

import json
import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.scan_policy import DEFAULT_POLICY


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
print("scan policy defaults aligned")
