#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression checks for AST-DF feature extraction."""

import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.ast_df import ast_df_heuristic, extract_features, feature_vector

WEBSHELL_PHP = b"""<?php
$cmd = $_REQUEST['cmd'];
$fn = 'sys'.'tem';
eval(base64_decode($_POST['x']));
$fn($cmd);
?>
"""

BENIGN_PHP = b"""<?php
$name = isset($_GET['name']) ? $_GET['name'] : 'guest';
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>
"""

policy = {
    "ast_df_enabled": True,
    "ast_df_model_path": "models/ast_df_missing.pkl",
    "ast_df_min_probability": 0.70,
    "ast_df_score_cap": 90,
    "ast_df_max_file_bytes": 2097152,
}

webshell = extract_features(WEBSHELL_PHP, ".php", "upload/shell.php", policy)
benign = extract_features(BENIGN_PHP, ".php", "public/index.php", policy)

assert webshell["source_count"] >= 2, webshell
assert webshell["sink_count"] >= 2, webshell
assert webshell["decode_count"] >= 1, webshell
assert webshell["dynamic_dispatch_count"] >= 1, webshell
assert webshell["suspicious_score"] > benign["suspicious_score"], (webshell, benign)
assert len(feature_vector(webshell)) == len(feature_vector(benign))

score, reason = ast_df_heuristic(
    WEBSHELL_PHP, ".php", "upload/shell.php", policy, app_path=APP_ROOT)
assert (score, reason) == (0, None), (score, reason)

print("ast-df checks passed")
