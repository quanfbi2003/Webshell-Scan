#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thêm mẫu webshell vào libs/signature-base/custom/known_webshells.ssdeep."""

import argparse
import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.ssdeep_db import append_from_file, get_ssdeep_db_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("samples", nargs="+", help="File hoặc thư mục mẫu")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    out = args.output or get_ssdeep_db_path(APP_ROOT)
    added = 0
    for sample in args.samples:
        if os.path.isdir(sample):
            files = []
            for root, _, names in os.walk(sample):
                for name in names:
                    files.append(os.path.join(root, name))
        else:
            files = [sample]
        for fpath in files:
            ok, msg = append_from_file(fpath, out, source="build-ssdeep")
            if ok:
                added += 1
                print("Added: %s" % fpath)
            else:
                if msg != "already in database":
                    print("Skip %s: %s" % (fpath, msg))

    print("Added %s entries -> %s" % (added, out))


if __name__ == "__main__":
    main()
