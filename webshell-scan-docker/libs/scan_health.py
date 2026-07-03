# -*- coding: utf-8 -*-
"""Preflight checks, runtime counters, and scan summary logging."""

import os
import traceback

STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_ERROR = "ERROR"
STATUS_SKIP = "SKIP"


class ScanStats(object):
    """Thread-safe counters for one scan run."""

    def __init__(self):
        self._data = {}
        self._lock = None

    def set_lock(self, lock):
        self._lock = lock

    def inc(self, key, amount=1):
        if self._lock:
            with self._lock:
                self._data[key] = self._data.get(key, 0) + amount
        else:
            self._data[key] = self._data.get(key, 0) + amount

    def merge(self, other):
        if not other:
            return
        if self._lock:
            with self._lock:
                for key, val in other.items():
                    self._data[key] = self._data.get(key, 0) + int(val)
        else:
            for key, val in other.items():
                self._data[key] = self._data.get(key, 0) + int(val)

    def get(self, key, default=0):
        return self._data.get(key, default)

    def snapshot(self):
        if self._lock:
            with self._lock:
                return dict(self._data)
        return dict(self._data)


def _check_result(name, status, message, detail=None):
    return {"component": name, "status": status, "message": message, "detail": detail or ""}


def run_preflight_checks(scanner, logger=None):
    """
    Verify subsystems before scanning. Returns list of check dicts.
    Does not exit on WARN; ERROR on critical (YARA compile, policy file corrupt).
    """
    results = []
    app_path = scanner.app_path

    def log_check(check):
        if not logger:
            return
        level = "INFO" if check["status"] == STATUS_OK else (
            "WARNING" if check["status"] == STATUS_WARN else "ERROR"
        )
        msg = "[Health] %s: %s — %s" % (check["status"], check["component"], check["message"])
        if check.get("detail"):
            msg += " (%s)" % check["detail"]
        logger.log(level, "Health", msg)

    # --- Policy ---
    policy_path = os.path.join(app_path, "config", "scan-policy.json")
    if os.path.isfile(policy_path):
        try:
            import json
            with open(policy_path, "r", encoding="utf-8") as handle:
                json.load(handle)
            results.append(_check_result(
                "scan-policy.json", STATUS_OK, "readable and valid JSON", policy_path))
        except Exception as exc:
            results.append(_check_result(
                "scan-policy.json", STATUS_ERROR, "invalid JSON", str(exc)))
    else:
        results.append(_check_result(
            "scan-policy.json", STATUS_WARN, "missing, using built-in defaults", policy_path))

    policy = getattr(scanner, "effective_policy", None) or getattr(scanner, "scan_policy", {})
    if policy.get("deobfuscate_enabled", True):
        results.append(_check_result("policy.deobfuscate", STATUS_OK, "enabled"))
    else:
        results.append(_check_result("policy.deobfuscate", STATUS_WARN, "disabled in policy"))

    # --- YARA ---
    if not getattr(scanner, "yara_rules", None):
        results.append(_check_result("YARA", STATUS_ERROR, "no compiled rules"))
    else:
        # Count total rules across all compiled sets by scanning the source rule count
        n_sets = len(scanner.yara_rules)
        # Report number of compiled rule sets (each set may contain many rules)
        results.append(_check_result("YARA", STATUS_OK, "compiled rule set(s) loaded", "sets=%s" % n_sets))

    obfusc_path = os.path.join(scanner.custom_path, "yara_obfuscate.yar")
    if os.path.isfile(obfusc_path):
        results.append(_check_result("yara_obfuscate.yar", STATUS_OK, "present in custom/"))
    else:
        results.append(_check_result("yara_obfuscate.yar", STATUS_WARN, "file not found"))

    # Smoke: match known obfuscated sample string
    try:
        import yara
        smoke = b'<?php eval(base64_decode("c3lzdGVtKCRfR0VUWydjJ10pOw=="));'
        externals = {
            'filename': 'test.php', 'filepath': '/tmp/test.php', 'extension': '.php',
            'filetype': 'UNKNOWN', 'md5': '-', 'owner': 'dummy',
        }
        matched = False
        for rules in scanner.yara_rules:
            if rules.match(data=smoke, externals=externals):
                matched = True
                break
        if matched:
            results.append(_check_result("YARA.smoke_obfusc", STATUS_OK, "matched test obfuscated PHP payload"))
        else:
            results.append(_check_result(
                "YARA.smoke_obfusc", STATUS_WARN,
                "no match on built-in smoke sample (rules may need update)"))
    except Exception as exc:
        results.append(_check_result("YARA.smoke_obfusc", STATUS_ERROR, "smoke test failed", str(exc)))

    # --- Deobfuscate ---
    try:
        from libs.deobfuscate import iter_deobfuscated_layers
        sample = b'<?php eval(base64_decode("ZXZhbCgkX1BPU1RbJ10pOw=="));'
        layers = list(iter_deobfuscated_layers(sample, policy))
        layer_names = [name for name, _ in layers]
        if len(layers) >= 2:
            results.append(_check_result(
                "deobfuscate", STATUS_OK, "extracted layers", "layers=%s" % ",".join(layer_names)))
        else:
            results.append(_check_result(
                "deobfuscate", STATUS_WARN, "only raw layer from smoke test", "layers=%s" % layer_names))
    except Exception as exc:
        results.append(_check_result("deobfuscate", STATUS_ERROR, "module failed", str(exc)))

    # --- Entropy ---
    try:
        from libs.heuristics import entropy_heuristic, shannon_entropy
        ent = shannon_entropy(b"\x00" * 100 + b"\xff" * 100)
        sub, reason = entropy_heuristic(
            b"<?php " + b"x" * 500, ".php", "/var/www/uploads/shell.php",
            policy, paranoid=False,
        )
        results.append(_check_result(
            "entropy", STATUS_OK, "module OK",
            "shannon_smoke=%.2f upload_hit=%s" % (ent, bool(reason))))
    except Exception as exc:
        results.append(_check_result("entropy", STATUS_ERROR, "module failed", str(exc)))

    # --- Source/Sink ---
    try:
        from libs.heuristics import source_sink_heuristic
        sub, reason = source_sink_heuristic(
            b"<?php $cmd=$_GET['cmd']; system($cmd); ?>",
            ".php",
            "/var/www/uploads/shell.php",
            policy,
            paranoid=False,
        )
        status = STATUS_OK if sub and reason else STATUS_WARN
        results.append(_check_result(
            "source_sink", status, "request-to-exec heuristic",
            "score=%s hit=%s" % (sub, bool(reason))))
    except Exception as exc:
        results.append(_check_result("source_sink", STATUS_ERROR, "module failed", str(exc)))

    # --- Behavior graph ---
    try:
        from libs.heuristics import behavior_graph_heuristic
        sub, reason = behavior_graph_heuristic(
            b"<?php $f='system'; $x=base64_decode($_POST['x']); $f($x); ?>",
            ".php",
            "/var/www/uploads/bg.php",
            policy,
            paranoid=False,
        )
        status = STATUS_OK if sub and reason else STATUS_WARN
        results.append(_check_result(
            "behavior_graph", status, "static behavior graph heuristic",
            "score=%s hit=%s" % (sub, bool(reason))))
    except Exception as exc:
        results.append(_check_result("behavior_graph", STATUS_ERROR, "module failed", str(exc)))

    # --- Webshell capability modules ---
    try:
        from libs.heuristics import webshell_capability_heuristic
        sub, reason = webshell_capability_heuristic(
            b"<?php function main($cmd){ system($cmd); } ?>",
            ".php",
            "/var/www/html/Cmd.php",
            policy,
            paranoid=False,
        )
        status = STATUS_OK if sub and reason else STATUS_WARN
        results.append(_check_result(
            "webshell_capability", status, "module-style webshell heuristic",
            "score=%s hit=%s" % (sub, bool(reason))))
        java_sample = (
            b"net/rebeyond/behinder/payload/java/Cmd\x00"
            b"javax/servlet/jsp/PageContext\x00javax/servlet/ServletRequest\x00"
            b"getInputStream\x00java/lang/Runtime\x00getRuntime\x00exec\x00cmd.exe"
        )
        jsub, jreason = webshell_capability_heuristic(
            java_sample,
            ".class",
            "/tmp/Cmd.class",
            policy,
            paranoid=False,
        )
        jstatus = STATUS_OK if jsub and jreason else STATUS_WARN
        results.append(_check_result(
            "webshell_capability.java_class", jstatus,
            "Behinder/JSP class payload heuristic",
            "score=%s hit=%s" % (jsub, bool(jreason))))
        tail_policy = dict(policy)
        tail_policy["webshell_capability_max_file_bytes"] = 4096
        tail_sample = (
            b'<?php function Phyo3($text){return chr(65);} $origin="37-'
            + (b"408-" * 96)
            + b'";'
            + (b"A" * 6000)
            + b'$sip=Phyo3($origin); $password="67c8cd5679a140e7904a8d309606039a"; eval($sip); ?>'
        )
        tsub, treason = webshell_capability_heuristic(
            tail_sample,
            ".php",
            "/tmp/large-tail.php",
            tail_policy,
            paranoid=False,
        )
        tstatus = STATUS_OK if tsub and treason else STATUS_WARN
        results.append(_check_result(
            "webshell_capability.large_php_tail", tstatus,
            "large PHP head/tail payload heuristic",
            "score=%s hit=%s" % (tsub, bool(treason))))
        edge_samples = [
            (b'<?php @include "\\x2fh\\x6fm\\x65/\\x77e\\x62/file.ico";', ".php", "/tmp/include.php"),
            (b'<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:scriptlet>{code}</jsp:scriptlet></jsp:root>', ".jspx", "/tmp/shell.jspx"),
            (b'terminal_port_path="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server";termport=wsh.regread(terminal_port_path)', ".asp", "/tmp/duankou.asp"),
            (b'<% Set x = Server.CreateObject("MSXML2.ServerXMLHTTP"): x.open "GET", request("url"), false: x.send(): response.write x.responseText %>', ".asp", "/tmp/proxy.asp"),
            (b'<%@ page import="java.net.*" %><% String url=request.getParameter("u"); new java.net.URL(url).openConnection().getInputStream(); %>', ".jsp", "/tmp/proxy.jsp"),
            (b'<?php // pwd=D8OWX2Y\npreg_replace(chr(47).chr(100).chr(117).chr(111).chr(115).chr(111).chr(102).chr(116).chr(47).chr(105).chr(115).chr(101), chr(0x40).chr(0x65).chr(0x76).chr(97).chr(0x6c).chr(0x28).chr(0x27).chr(0x40).chr(101).chr(0x76), "x");', ".php", "/tmp/preg_replace.php"),
        ]
        edge_hits = 0
        for data, ext, path in edge_samples:
            esub, ereason = webshell_capability_heuristic(data, ext, path, policy, paranoid=False)
            if esub and ereason:
                edge_hits += 1
        estatus = STATUS_OK if edge_hits == len(edge_samples) else STATUS_WARN
        results.append(_check_result(
            "webshell_capability.edge_cases", estatus,
            "PHP/JSPX/ASP edge module heuristics",
            "hits=%s/%s" % (edge_hits, len(edge_samples))))
    except Exception as exc:
        results.append(_check_result("webshell_capability", STATUS_ERROR, "module failed", str(exc)))

    # --- SSDeep ---
    if not getattr(scanner, "effective_policy", {}).get("ssdeep_enabled_effective", True):
        results.append(_check_result(
            "SSDeep", STATUS_OK, "disabled by runtime policy", "--no-ssdeep"))
    else:
        try:
            import pyssdeep  # noqa: F401
            if getattr(scanner, "ssdeep_signatures", None):
                n = len(scanner.ssdeep_signatures)
                results.append(_check_result("SSDeep", STATUS_OK, "pyssdeep OK, signatures loaded", "count=%s" % n))
            else:
                results.append(_check_result(
                    "SSDeep", STATUS_WARN, "pyssdeep OK but known_webshells.ssdeep empty/missing"))
        except ImportError:
            results.append(_check_result(
                "SSDeep", STATUS_WARN, "pyssdeep not installed — fuzzy hash disabled", "pip install pyssdeep"))

    # --- VT → SSDeep (trình duyệt, không API) ---
    if getattr(scanner, "effective_policy", {}).get("vt_ssdeep_enabled"):
        results.append(_check_result(
            "VT", STATUS_OK,
            "VT→SSDeep via browser (no API)",
            "interactive after scan; or: python tools/vt-check.py -i logs/ --add-ssdeep",
        ))
    else:
        results.append(_check_result(
            "VT", STATUS_OK,
            "VT→SSDeep disabled",
            "use --vt-ssdeep or tools/vt-check.py",
        ))

    # --- Hash IOC ---
    n_md5 = len(getattr(scanner, "hashes_md5", {}) or {})
    n_sha1 = len(getattr(scanner, "hashes_sha1", {}) or {})
    n_sha256 = len(getattr(scanner, "hashes_sha256", {}) or {})
    results.append(_check_result(
        "hash_IOC", STATUS_OK if (n_md5 or n_sha1 or n_sha256) else STATUS_WARN,
        "MD5=%s SHA1=%s SHA256=%s" % (n_md5, n_sha1, n_sha256)))

    n_filename = len(getattr(scanner, "filename_iocs", []) or [])
    results.append(_check_result(
        "filename_IOC", STATUS_OK if n_filename else STATUS_WARN,
        "regex count=%s" % n_filename))

    # --- Excludes ---
    n_ex = len(getattr(scanner, "fullExcludes", []) or [])
    results.append(_check_result("excludes.cfg", STATUS_OK, "regex patterns loaded", "count=%s" % n_ex))

    for check in results:
        log_check(check)

    return results


def log_preflight_summary(logger, results):
    """One-line summary after all checks."""
    ok = sum(1 for c in results if c["status"] == STATUS_OK)
    warn = sum(1 for c in results if c["status"] == STATUS_WARN)
    err = sum(1 for c in results if c["status"] == STATUS_ERROR)
    logger.log(
        "NOTICE", "Health",
        "Preflight: %s OK, %s WARN, %s ERROR — scan %s"
        % (ok, warn, err, "blocked" if err else "can proceed"),
    )
    if err:
        failed = [c["component"] for c in results if c["status"] == STATUS_ERROR]
        logger.log("ERROR", "Health", "Failed components: %s" % ", ".join(failed))


def log_runtime_summary(logger, stats, findings_count=0, gray_zone_count=0, all_files_count=0):
    """Log per-engine usage counts after scan."""
    s = stats.snapshot() if isinstance(stats, ScanStats) else stats
    logger.log("NOTICE", "Health", "=== Runtime scan summary ===")
    lines = [
        ("files_processed", "Files processed"),
        ("files_errors", "File processing errors"),
        ("hash_ioc_hits", "Malware hash IOC matches"),
        ("ssdeep_hits", "SSDeep matches"),
        ("entropy_hits", "Entropy heuristic hits"),
        ("behavior_graph_hits", "Behavior graph heuristic hits"),
        ("deobfuscate_layers", "Deobfuscate layers scanned"),
        ("yara_matches_raw", "YARA matches (raw layer)"),
        ("yara_matches_deobfuscated", "YARA matches (deobfuscated layers)"),
        ("yara_timeouts", "YARA scan timeouts"),
        ("archive_files_scanned", "Files scanned inside archives"),
    ]
    for key, label in lines:
        val = s.get(key, 0)
        if val or key in ("files_processed", "yara_timeouts", "files_errors"):
            logger.log("INFO", "Health", "%s: %s" % (label, val))
    logger.log("INFO", "Health", "Findings (main report): %s" % findings_count)
    logger.log("INFO", "Health", "Gray zone entries: %s" % gray_zone_count)
    logger.log("INFO", "Health", "All files logged: %s" % all_files_count)

    if s.get("yara_timeouts", 0) > 0:
        logger.log("WARNING", "Health",
                   "YARA timeouts occurred — increase timeout or exclude large dirs")
    if s.get("files_errors", 0) > 0:
        logger.log("WARNING", "Health", "Some files failed processing — search log for ERROR FileScan")
    if s.get("deobfuscate_layers", 0) == 0 and s.get("files_processed", 0) > 100:
        logger.log("NOTICE", "Health",
                   "No deobfuscate layers (normal if no PHP/obfusc paths in scan target)")
