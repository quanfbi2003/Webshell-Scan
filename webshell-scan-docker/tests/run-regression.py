#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick regression: YARA + deobfuscate on tests/samples/."""

import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

import yara
from libs.deobfuscate import iter_deobfuscated_layers
from libs.heuristics import source_sink_heuristic
from libs.scan_policy import load_scan_policy

SAMPLES = os.path.join(APP_ROOT, "tests", "samples")
CUSTOM_YARA = os.path.join(APP_ROOT, "libs", "signature-base", "custom")

EXPECTED = {
    "benign_": {"source_sink": False, "yara": False},
    "clean_": {"source_sink": False, "yara": False},
    "source_sink_": {"source_sink": True},
    "obfusc_": {"deobfuscate": True},
}


def compile_custom_rules():
    filepaths = {}
    for name in sorted(os.listdir(CUSTOM_YARA)):
        if name.endswith((".yar", ".yara")):
            namespace = "custom_%d" % len(filepaths)
            filepaths[namespace] = os.path.join(CUSTOM_YARA, name)
    return yara.compile(filepaths=filepaths)


def main():
    policy = load_scan_policy(APP_ROOT)
    compiled = compile_custom_rules()
    failures = []
    print("Regression samples in %s\n" % SAMPLES)
    for fname in sorted(os.listdir(SAMPLES)):
        path = os.path.join(SAMPLES, fname)
        if not os.path.isfile(path):
            continue
        data = open(path, "rb").read()
        ext = os.path.splitext(fname)[1].lower()
        externals = {
            "filename": fname, "filepath": path, "extension": ext,
            "filetype": "UNKNOWN", "md5": "-", "owner": "dummy",
        }
        hits = []
        layers = list(iter_deobfuscated_layers(data, policy))
        for layer_name, layer_data in layers:
            matches = compiled.match(data=layer_data, externals=externals)
            for m in matches:
                hits.append("%s:%s" % (layer_name, m.rule))
        ss_score, ss_reason = source_sink_heuristic(data, ext, path, policy)
        status = "MATCH" if hits else "clean"
        print("%-32s %-7s layers=%-2s source_sink=%-3s %s" % (
            fname, status, len(layers), ss_score, hits))

        for prefix, checks in EXPECTED.items():
            if not fname.startswith(prefix):
                continue
            if checks.get("source_sink") is True and not ss_score:
                failures.append("%s expected source_sink hit" % fname)
            if checks.get("source_sink") is False and ss_score:
                failures.append("%s unexpected source_sink hit: %s" % (fname, ss_reason))
            if checks.get("yara") is False and hits:
                failures.append("%s unexpected YARA hit: %s" % (fname, hits))
            if checks.get("deobfuscate") is True and len(layers) < 2:
                failures.append("%s expected deobfuscated layer" % fname)

    if failures:
        print("\nFAIL")
        for item in failures:
            print(" - %s" % item)
        return 1
    print("\nPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
