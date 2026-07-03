#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression checks for package/archive false-positive guard."""

import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)

from libs.heuristics import library_fp_gate


COMPOSER_PHAR = b"""
<?php
namespace Composer\\Util;
class ProcessExecutor {
    public function execute($command) {
        return proc_open($command, array(), $pipes);
    }
}
class AutoloadGenerator {
    public function dump() { return file_get_contents(__FILE__); }
}
"""

JSP_WEBSHELL = b"""
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
String out = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
response.getWriter().println(out);
%>
"""

assert library_fp_gate(
    "backup/home/webdata/app/composer.phar", ".phar", COMPOSER_PHAR,
    {"behavior_graph", "webshell_capability", "yara"}, [], {},
), "composer.phar library should be gated out of main findings"

assert not library_fp_gate(
    "upload/shell.jsp", ".jsp", JSP_WEBSHELL,
    {"source_sink", "behavior_graph", "webshell_capability", "yara"}, [], {},
), "request-to-exec JSP webshell must not be gated"

print("fp guard checks passed")
