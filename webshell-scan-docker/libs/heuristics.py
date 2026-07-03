# -*- coding: utf-8 -*-
"""Entropy and path heuristics for upload / obfuscated webshells."""

import math
import os
import re

_SCANNABLE_TEXT_EXT = {
    ".php", ".phtml", ".php5", ".php7", ".phar", ".inc",
    ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".cfm",
    ".js", ".cgi", ".pl",
}

_PHP_EXT = {".php", ".phtml", ".php5", ".php7", ".phar", ".inc"}
_JSP_EXT = {".jsp", ".jspx"}
_ASPNET_EXT = {".asp", ".aspx", ".ashx", ".asmx"}
_CFM_EXT = {".cfm", ".cfc"}
_SCRIPT_EXT = {".cgi", ".pl"}
_JAVA_ARTIFACT_EXT = {".class", ".java"}

_PHP_SOURCE_RE = (
    r"(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[|"
    r"\$HTTP_(?:GET|POST|COOKIE|SERVER|POST_FILES)_VARS\s*\[|"
    r"php://input|filter_input\s*\(|getallheaders\s*\(|apache_request_headers\s*\()"
)
_PHP_SINK_RE = r"\b(?:eval|assert|system|shell_exec|passthru|proc_open|popen|exec)\s*\("
_PHP_ASSIGN_RE = re.compile(
    r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]{0,300}" + _PHP_SOURCE_RE,
    re.IGNORECASE | re.DOTALL,
)

_JSP_SOURCE_RE = r"\brequest\s*\.\s*(?:getParameter|getParameterMap|getHeader|getInputStream|getReader)\s*\("
_JSP_SINK_RE = (
    r"(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|"
    r"\.defineClass\s*\(|ClassLoader|Class\s*\.\s*forName|"
    r"\.getDeclaredMethod\s*\(|\.invoke\s*\()"
)

_ASPNET_SOURCE_RE = (
    r"(?:Request\s*\.\s*(?:QueryString|Form|Params|Cookies|ServerVariables|BinaryRead|InputStream)|"
    r"Request\s*\[)"
)
_ASPNET_SINK_RE = (
    r"(?:ProcessStartInfo|Process\s*\.\s*Start|CreateObject\s*\(\s*['\"]WScript\.Shell|"
    r"\bEval\s*\(|\bExecute\s*\(|\bShell\s*\(|cmd\.exe|powershell|"
    r"Assembly\s*\.\s*Load|GetType\s*\(|InvokeMember\s*\()"
)


def _decode_text(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding, errors="replace")
        except Exception:
            continue
    return ""


def _first_matches(pattern, text, limit=3):
    matches = []
    for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
        token = match.group(0)
        token = re.sub(r"\s+", " ", token).strip()
        matches.append(token[:80])
        if len(matches) >= limit:
            break
    return matches


def _has(pattern, text):
    return bool(re.search(pattern, text, re.IGNORECASE | re.DOTALL))


def _count_groups(patterns, text):
    hits = []
    for name, pattern in patterns:
        if _has(pattern, text):
            hits.append(name)
    return hits


def _java_has_tokens(text, tokens):
    return all(token.lower() in text.lower() for token in tokens)


def _php_direct_source_sink(text):
    return (
        re.search(_PHP_SINK_RE + r"[^;\n]{0,350}" + _PHP_SOURCE_RE, text, re.IGNORECASE | re.DOTALL)
        or re.search(_PHP_SOURCE_RE + r"[^;\n]{0,350}" + _PHP_SINK_RE, text, re.IGNORECASE | re.DOTALL)
    )


def _php_tainted_sink(text):
    tainted_vars = []
    for match in _PHP_ASSIGN_RE.finditer(text):
        var_name = match.group("var")
        if var_name not in tainted_vars:
            tainted_vars.append(var_name)
        if len(tainted_vars) >= 8:
            break

    for var_name in tainted_vars:
        escaped = re.escape(var_name)
        if re.search(_PHP_SINK_RE + r"[^;\n]{0,300}" + escaped, text, re.IGNORECASE | re.DOTALL):
            return var_name
        if re.search(escaped + r"\s*\([^;\n]{0,300}" + _PHP_SOURCE_RE, text, re.IGNORECASE | re.DOTALL):
            return var_name
    return None


def shannon_entropy(data):
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    length = len(data)
    if length == 0:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(data):
    if not data:
        return 1.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def path_matches_upload_patterns(file_path, patterns):
    if not file_path or not patterns:
        return False
    path_norm = file_path.replace("\\", "/").lower()
    for pattern in patterns:
        p = pattern.lower().strip("/")
        if not p:
            continue
        if re.search(r"(^|[/])%s([/]|$)" % re.escape(p), path_norm):
            return True
    return False


def extension_looks_like_code(extension):
    return (extension or "").lower() in _SCANNABLE_TEXT_EXT


def library_fp_gate(file_path, extension, file_data, evidence_groups, reasons, policy):
    """Return reason when a package/library hit should stay out of main findings."""
    if not policy.get("library_fp_guard_enabled", True):
        return None

    path = (file_path or "").replace("\\", "/").lower()
    base = os.path.basename(path)
    package_context = (
        base == "composer.phar"
        or "/vendor/" in path
        or "/node_modules/" in path
        or "/meta-inf/resources/" in path
        or ".jar_" in path
        or "_extracted/" in path and any(x in path for x in ("ckeditor", "codemirror", "primefaces", "tika-", "jce.jar"))
    )
    if not package_context:
        return None

    text = _decode_text(file_data[:1024 * 1024] if isinstance(file_data, bytes) else file_data)
    name_and_text = base + "\n" + text[:8192]
    webshell_marker = _has(
        r"web\s*shell|webshell|cmdshell|back\s*shell|antsword|behinder|chopper|caidao|cknife|c99|wso|b374k|p0wny|phpbash",
        name_and_text,
    )
    request_exec = (
        (_has(r"\brequest\s*\.\s*(?:getParameter|getHeader|getInputStream|getReader)\s*\(", text) and _has(_JSP_SINK_RE, text))
        or (_has(r"\$_(?:GET|POST|REQUEST|FILES)\s*\[|php://input", text) and _has(_PHP_SINK_RE, text))
        or (_has(r"Request\s*\.\s*(?:QueryString|Form|Params|BinaryRead)|Request\s*\[", text) and _has(_ASPNET_SINK_RE, text))
    )
    if webshell_marker or request_exec or "hash_ioc" in evidence_groups or "ssdeep" in evidence_groups:
        return None

    return "package/library context without direct request-to-exec webshell evidence"


def entropy_heuristic(file_data, extension, file_path, policy, paranoid=False):
    """
    Return (subscore, reason_text) or (0, None).
    """
    if not policy.get("entropy_enabled_effective", policy.get("entropy_enabled", True)):
        return 0, None

    upload_only = policy.get("entropy_upload_only", True)
    if upload_only and not path_matches_upload_patterns(
        file_path, policy.get("upload_path_patterns") or []
    ):
        if not paranoid:
            return 0, None

    if not extension_looks_like_code(extension):
        return 0, None

    if not file_data or len(file_data) > 1024 * 1024:
        return 0, None

    entropy = shannon_entropy(file_data)
    threshold = float(policy.get("entropy_threshold", 7.2))
    subscore = int(policy.get("entropy_subscore", 15))
    if paranoid:
        subscore += int(policy.get("paranoid_entropy_boost", 10))
        threshold -= 0.2

    ratio = printable_ratio(file_data)
    reasons = []

    if entropy >= threshold:
        reasons.append("entropy=%.2f>=%.1f" % (entropy, threshold))
    if ratio < 0.55 and len(file_data) > 64:
        reasons.append("printable_ratio=%.0f%%" % (ratio * 100))

    if not reasons:
        return 0, None

    return subscore, "Heuristic Entropy SUBSCORE: %s DESC: %s" % (subscore, ", ".join(reasons))


def source_sink_heuristic(file_data, extension, file_path, policy, paranoid=False):
    """
    Return (subscore, reason_text) when request-controlled input reaches an execution sink.
    The heuristic requires a source and a sink together; isolated keywords are ignored.
    """
    ext = (extension or "").lower()
    if ext not in (_PHP_EXT | _JSP_EXT | _ASPNET_EXT):
        return 0, None
    if not file_data or len(file_data) > int(policy.get("source_sink_max_file_bytes", 2 * 1024 * 1024)):
        return 0, None

    text = _decode_text(file_data)
    if not text:
        return 0, None

    reasons = []
    score = int(policy.get("source_sink_base_subscore", 35))
    max_score = int(policy.get("source_sink_max_subscore", 75))
    source_pattern = sink_pattern = None
    platform = "generic"

    if ext in _PHP_EXT:
        platform = "php"
        source_pattern = _PHP_SOURCE_RE
        sink_pattern = _PHP_SINK_RE
        if _php_direct_source_sink(text):
            score += 15
            reasons.append("direct_request_to_sink")
        tainted_var = _php_tainted_sink(text)
        if tainted_var:
            score += 20
            reasons.append("tainted_variable=%s" % tainted_var)
        if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\(", text) and re.search(source_pattern, text, re.IGNORECASE):
            score += 10
            reasons.append("variable_function_call")
    elif ext in _JSP_EXT:
        platform = "jsp"
        source_pattern = _JSP_SOURCE_RE
        sink_pattern = _JSP_SINK_RE
        if re.search(r"(?:ClassLoader|defineClass|Class\s*\.\s*forName|\.invoke\s*\()", text, re.IGNORECASE):
            score += 15
            reasons.append("reflection_or_classloader")
        if re.search(r"(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder)", text, re.IGNORECASE):
            score += 15
            reasons.append("process_execution")
    elif ext in _ASPNET_EXT:
        platform = "aspnet"
        source_pattern = _ASPNET_SOURCE_RE
        sink_pattern = _ASPNET_SINK_RE
        if re.search(r"(?:ProcessStartInfo|Process\s*\.\s*Start|CreateObject\s*\(\s*['\"]WScript\.Shell)", text, re.IGNORECASE):
            score += 15
            reasons.append("process_execution")
        if re.search(r"(?:Assembly\s*\.\s*Load|GetType\s*\(|InvokeMember\s*\()", text, re.IGNORECASE):
            score += 10
            reasons.append("reflection_or_loader")

    sources = _first_matches(source_pattern, text) if source_pattern else []
    sinks = _first_matches(sink_pattern, text) if sink_pattern else []
    if not sources or not sinks:
        return 0, None

    if path_matches_upload_patterns(file_path, policy.get("upload_path_patterns") or []):
        score += 5
        reasons.append("upload_path")
    if paranoid:
        score += int(policy.get("source_sink_paranoid_boost", 10))

    score = min(score, max_score)
    detail = "platform=%s sources=%s sinks=%s flow=%s" % (
        platform,
        "|".join(sources),
        "|".join(sinks),
        ",".join(reasons) if reasons else "source_sink_cooccurrence",
    )
    return score, "Heuristic SourceSink SUBSCORE: %s DESC: %s" % (score, detail)


def behavior_graph_heuristic(file_data, extension, file_path, policy, paranoid=False):
    """
    Build a lightweight static behavior graph and score combinations such as:
    request source -> decoder/obfuscation -> dynamic dispatch -> execution sink.

    The graph is intentionally regex-based so it can run on hostile samples
    without executing or importing them. Isolated dangerous words are ignored;
    a finding needs a suspicious path through multiple behavior groups.
    """
    if not policy.get("behavior_graph_enabled", True):
        return 0, None

    ext = (extension or "").lower()
    base_name = os.path.basename(file_path or "").lower()
    allowed = _PHP_EXT | _JSP_EXT | _ASPNET_EXT | _CFM_EXT | _SCRIPT_EXT | _JAVA_ARTIFACT_EXT
    if base_name.startswith("._") or ext not in allowed or not file_data:
        return 0, None

    max_file_bytes = max(8192, int(policy.get("behavior_graph_max_file_bytes", 5 * 1024 * 1024)))
    if isinstance(file_data, str):
        analysis_data = file_data
    elif len(file_data) > max_file_bytes:
        head_bytes = max(4096, max_file_bytes // 2)
        tail_bytes = max(4096, max_file_bytes - head_bytes)
        analysis_data = (
            file_data[:head_bytes]
            + b"\n/* middle bytes omitted for behavior graph */\n"
            + file_data[-tail_bytes:]
        )
    else:
        analysis_data = file_data

    text = _decode_text(analysis_data)
    if not text:
        return 0, None

    name_and_text = base_name + "\n" + text[:16384]
    platform = "generic"
    if ext in _PHP_EXT:
        platform = "php"
    elif ext in _JSP_EXT or ext in _JAVA_ARTIFACT_EXT:
        platform = "java"
    elif ext in _ASPNET_EXT:
        platform = "aspnet"
    elif ext in _CFM_EXT:
        platform = "cfm"
    elif ext in _SCRIPT_EXT:
        platform = "script"

    node_patterns = {
        "source": [
            ("php_request", _PHP_SOURCE_RE),
            ("jsp_request", _JSP_SOURCE_RE),
            ("aspnet_request", _ASPNET_SOURCE_RE),
            ("cfm_request", r"\b(?:URL|FORM|COOKIE|CGI)\s*\.|<cfparam|<cfargument"),
            ("classic_request", r"\bRequest\s*\(\s*['\"][^'\"]{1,80}['\"]\s*\)"),
            ("servlet_context", r"HttpServletRequest|ServletRequest|PageContext|getAttribute\s*\(|getRequest\s*\("),
        ],
        "decode": [
            ("base64", r"\b(?:base64_decode|base64_encode|Base64\.getDecoder|Convert\.FromBase64String|atob)\b"),
            ("compression", r"\b(?:gzinflate|gzuncompress|gzdecode|zlib_decode|Inflater|GZIPInputStream|DeflateStream)\b"),
            ("url_decode", r"\b(?:urldecode|rawurldecode|URLDecoder\.decode|HttpUtility\.UrlDecode|unescape)\s*\("),
            ("string_reverse", r"\b(?:strrev|array_reverse|Reverse\s*\(|StringBuilder\s*\([^)]*\)\s*\.reverse)\b"),
            ("pack_or_hex", r"\b(?:pack|hex2bin|String\.fromCharCode)\s*\("),
            ("crypto_or_xor", r"\b(?:mcrypt_|openssl_decrypt|Cipher\.getInstance|AesManaged|RijndaelManaged|xor|XOR)\b"),
        ],
        "dynamic_dispatch": [
            ("php_variable_function", r"\$\$[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,160}\)"),
            ("php_callback", r"\b(?:call_user_func|call_user_func_array|create_function|ReflectionFunction|ReflectionClass)\s*\("),
            ("php_preg_e", r"preg_replace\s*\([^;]{0,240}/[a-z]*e[a-z]*"),
            ("java_reflection", r"\b(?:Class\.forName|getDeclaredMethod|getMethod|invoke|Method\.class|Constructor\.class)\b"),
            ("java_classloader", r"\b(?:ClassLoader|defineClass|loadClass|URLClassLoader)\b"),
            ("dotnet_reflection", r"\b(?:Assembly\.Load|GetType\s*\(|InvokeMember\s*\(|Activator\.CreateInstance)\b"),
            ("asp_eval", r"\b(?:Eval|Execute|ExecuteGlobal|Server\.Execute)\s*\("),
        ],
        "exec_sink": [
            ("php_exec", _PHP_SINK_RE),
            ("java_exec", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|ProcessBuilder\s*\("),
            ("dotnet_exec", r"ProcessStartInfo|Process\s*\.\s*Start|cmd\.exe|powershell"),
            ("classic_shell", r"CreateObject\s*\(\s*['\"]WScript\.Shell|WScript\.Shell|Shell\.Application"),
            ("cfexecute", r"<cfexecute\b|\bcfexecute\b"),
        ],
        "file_ops": [
            ("php_file", r"\b(?:fopen|fwrite|fread|file_get_contents|file_put_contents|unlink|chmod|mkdir|rmdir|rename|copy|scandir|readdir|opendir|move_uploaded_file)\s*\("),
            ("archive_file", r"\b(?:ZipArchive|PharData|tar_open|compressSrcDir|unCompress)\b"),
            ("java_file", r"java[/\.]io[/\.]File|FileOutputStream|FileInputStream|RandomAccessFile|Files\.write"),
            ("dotnet_file", r"\b(?:FileStream|StreamWriter|DirectoryInfo|FileInfo|File\.WriteAll|File\.ReadAll|Server\.MapPath)\b"),
            ("asp_stream", r"ADODB\.Stream|Scripting\.FileSystemObject"),
            ("cf_file", r"<cf(?:file|directory)\b|CFFILE|CFDIRECTORY"),
        ],
        "network": [
            ("php_socket", r"\b(?:socket_create|socket_connect|socket_bind|socket_listen|fsockopen|pfsockopen|stream_socket_client|curl_exec)\s*\("),
            ("java_net", r"java[/\.]net[/\.](?:Socket|URL|URLConnection|HttpURLConnection)|openConnection\s*\(|AsynchronousSocketChannel|InetSocketAddress"),
            ("dotnet_net", r"\b(?:TcpClient|HttpWebRequest|WebClient|System\.Net\.Sockets)\b"),
            ("asp_http", r"MSXML2\.ServerXMLHTTP|ServerXMLHTTP|WinHttp\.WinHttpRequest|XMLHTTP"),
            ("cf_http", r"<cfhttp\b|CFHTTP"),
        ],
        "database": [
            ("php_db", r"\b(?:mysqli?_connect|mysqli?_query|mysql_query|pg_connect|sqlite|PDO\s*\(|sqlsrv_|oci_connect)\b"),
            ("java_db", r"java[/\.]sql|DriverManager\.getConnection|PreparedStatement|ResultSet"),
            ("dotnet_db", r"\b(?:SqlConnection|SqlCommand|OleDbConnection|ExecuteReader|ConnectionString)\b"),
            ("asp_db", r"ADODB\.Connection"),
            ("cf_db", r"<cfquery\b|CFQUERY"),
        ],
        "admin_introspection": [
            ("php_runtime", r"php_uname\s*\(|ini_get\s*\(\s*['\"]disable_functions|get_cfg_var\s*\(|open_basedir|proc/self/maps|disable_functions"),
            ("java_runtime", r"System\.getProperty|getRuntime\s*\(|ManagementFactory|getenv\s*\("),
            ("windows_admin", r"HKEY_LOCAL_MACHINE|Terminal Server|WinStations|PortNumber|System\.Security\.AccessControl"),
            ("iis_admin", r"COM\s*\(\s*['\"]IIS://|DirectoryServices|System\.Management"),
        ],
        "auth_channel": [
            ("credential_gate", r"\b(?:password|passwd|pwd|pass|auth|login|token|secret)\b|Pwd\s*="),
            ("known_channel", r"asenc|asoutput|7!I6|chopper|caidao|antsword|behinder|rebeyond|cknife|c9999"),
            ("webshell_terms", r"web\s*shell|webshell|cmdshell|back\s*shell|一句话|小马|大马|后门|命令执行"),
        ],
        "server_page": [
            ("server_markup", r"<%@?\s*page|<%|<jsp:(?:root|scriptlet|declaration|expression)\b|runat\s*=\s*['\"]server|<cf(?:script|set|try|switch|case)\b"),
            ("servlet_symbols", r"_jspService|JspWriter|HttpServletResponse|ServletOutputStream|Response\.Write|Response\.BinaryWrite"),
        ],
    }

    nodes = {}
    for node, patterns in node_patterns.items():
        hits = _count_groups(patterns, text)
        if node == "auth_channel":
            hits = _count_groups(patterns, name_and_text)
        if hits:
            nodes[node] = hits

    platform_hit_allowlist = {
        "php": {
            "source": {"php_request", "classic_request"},
            "dynamic_dispatch": {"php_variable_function", "php_callback", "php_preg_e"},
            "exec_sink": {"php_exec"},
        },
        "java": {
            "source": {"jsp_request", "servlet_context"},
            "dynamic_dispatch": {"java_reflection", "java_classloader"},
            "exec_sink": {"java_exec"},
        },
        "aspnet": {
            "source": {"aspnet_request", "classic_request"},
            "dynamic_dispatch": {"dotnet_reflection", "asp_eval"},
            "exec_sink": {"dotnet_exec", "classic_shell"},
        },
        "cfm": {
            "source": {"cfm_request"},
            "dynamic_dispatch": set(),
            "exec_sink": {"cfexecute"},
        },
    }
    if platform in platform_hit_allowlist:
        for node, allowed_hits in platform_hit_allowlist[platform].items():
            if node in nodes and allowed_hits:
                filtered_hits = [hit for hit in nodes[node] if hit in allowed_hits]
                if filtered_hits:
                    nodes[node] = filtered_hits
                else:
                    nodes.pop(node, None)

    chr_count = len(re.findall(r"\b(?:chr|Chr|String\.fromCharCode)\s*\(", text, re.IGNORECASE))
    escape_count = len(re.findall(r"(?:\\x[0-9a-fA-F]{2}|\\[0-7]{2,3}|%u[0-9a-fA-F]{4})", text))
    long_encoded_count = len(re.findall(r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]|['\"][0-9a-fA-F]{160,}['\"]", text))
    concat_count = len(re.findall(r"(?:\.\=|\+\=|\.\s*['\"]|['\"]\s*\.)", text))
    bitwise_count = len(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;\n]{0,180}(?:\^|\||&)[^;\n]{0,180};", text))
    if chr_count >= 12 or escape_count >= 20 or long_encoded_count >= 1 or concat_count >= 40 or bitwise_count >= 6:
        detail = []
        if chr_count >= 12:
            detail.append("chr=%d" % chr_count)
        if escape_count >= 20:
            detail.append("esc=%d" % escape_count)
        if long_encoded_count >= 1:
            detail.append("long_encoded=%d" % long_encoded_count)
        if concat_count >= 40:
            detail.append("concat=%d" % concat_count)
        if bitwise_count >= 6:
            detail.append("bitwise=%d" % bitwise_count)
        nodes["obfuscation_density"] = detail

    source = "source" in nodes
    decode = "decode" in nodes
    dynamic = "dynamic_dispatch" in nodes
    exec_sink = "exec_sink" in nodes
    file_ops = "file_ops" in nodes
    network = "network" in nodes
    database = "database" in nodes
    admin = "admin_introspection" in nodes
    auth = "auth_channel" in nodes
    server_page = "server_page" in nodes
    obfuscated = "obfuscation_density" in nodes

    edges = []
    score = 0
    reasons = []

    def add_edge(condition, edge, candidate, reason):
        nonlocal score
        if condition:
            edges.append(edge)
            score = max(score, candidate)
            reasons.append(reason)

    add_edge(source and decode and (dynamic or exec_sink), "source->decode->dispatch_or_exec", 78, "request_decoded_to_execution_path")
    add_edge(source and dynamic and (exec_sink or file_ops or network), "source->dispatch->dangerous_capability", 72, "request_driven_dynamic_dispatch")
    add_edge(source and exec_sink and (server_page or auth or platform in ("php", "java", "aspnet", "cfm")), "source->exec", 62, "request_to_execution_context")
    add_edge(decode and dynamic and exec_sink, "decode->dispatch->exec", 74, "decoded_dynamic_execution")
    add_edge(decode and exec_sink and (auth or obfuscated), "decode->exec", 68, "encoded_execution_channel")
    add_edge(source and (file_ops or database or network) and auth and (server_page or dynamic), "source->admin_capability", 58, "authenticated_admin_capability")
    add_edge(source and network and (auth or dynamic or server_page), "source->network", 56, "request_driven_proxy_or_tunnel")
    add_edge(source and file_ops and (auth or dynamic or obfuscated), "source->file_ops", 52, "request_driven_file_manager")
    add_edge((dynamic or exec_sink) and obfuscated and (source or decode or auth), "obfuscation->dispatch_or_exec", 66, "obfuscated_dispatch_or_execution")
    add_edge(platform == "java" and source and dynamic and (exec_sink or file_ops or network), "servlet->reflection_loader", 70, "java_servlet_reflection_or_loader")
    add_edge(platform == "aspnet" and source and dynamic and (exec_sink or file_ops), "aspnet->reflection_or_exec", 68, "aspnet_reflection_or_process")
    add_edge(platform == "cfm" and source and (exec_sink or file_ops or network), "cfm->dangerous_capability", 58, "cfm_request_capability")
    add_edge(platform == "script" and (exec_sink or network) and (auth or server_page or obfuscated), "script->exec_or_network", 50, "cgi_script_shell_capability")

    if not edges:
        return 0, None

    capability_bonus = min(10, 2 * sum(1 for flag in (file_ops, network, database, admin) if flag))
    score += capability_bonus
    if auth:
        score += 4
    if paranoid:
        score += int(policy.get("behavior_graph_paranoid_boost", 10))

    min_score = int(policy.get("behavior_graph_min_subscore", 35))
    max_score = int(policy.get("behavior_graph_max_subscore", 90))
    score = min(score, max_score)
    if score < min_score:
        return 0, None

    node_summary = []
    for node in (
        "source", "decode", "dynamic_dispatch", "exec_sink", "file_ops",
        "network", "database", "admin_introspection", "auth_channel",
        "server_page", "obfuscation_density",
    ):
        if node in nodes:
            node_summary.append("%s=%s" % (node, "|".join(nodes[node][:3])))

    detail = "platform=%s nodes=%s edges=%s reasons=%s" % (
        platform,
        ";".join(node_summary[:8]),
        "|".join(edges[:5]),
        "|".join(reasons[:5]),
    )
    return score, "Heuristic BehaviorGraph SUBSCORE: %s DESC: %s" % (score, detail)


def webshell_capability_heuristic(file_data, extension, file_path, policy, paranoid=False):
    """
    Detect webshell modules that expose dangerous capabilities but are invoked by a
    wrapper elsewhere (common in AntSword/CaiDao/Chopper style plugin sets).
    This intentionally scores combinations of capabilities, not isolated keywords.
    """
    if not policy.get("webshell_capability_enabled", True):
        return 0, None

    ext = (extension or "").lower()
    base_name = os.path.basename(file_path or "").lower()
    if base_name.startswith("._") or not file_data:
        return 0, None

    allowed = _PHP_EXT | _JSP_EXT | _ASPNET_EXT | _CFM_EXT | _SCRIPT_EXT | _JAVA_ARTIFACT_EXT
    if ext not in allowed:
        return 0, None
    if not file_data:
        return 0, None

    max_file_bytes = max(8192, int(policy.get("webshell_capability_max_file_bytes", 2 * 1024 * 1024)))
    if len(file_data) > max_file_bytes:
        head_bytes = max(4096, max_file_bytes // 2)
        tail_bytes = max(4096, max_file_bytes - head_bytes)
        analysis_data = (
            file_data[:head_bytes]
            + b"\n/* middle bytes omitted for heuristic window */\n"
            + file_data[-tail_bytes:]
        )
    else:
        analysis_data = file_data

    text = _decode_text(analysis_data)
    if not text:
        return 0, None

    path_lower = (file_path or "").replace("\\", "/").lower()
    score = 0
    reasons = []

    if ext in _JAVA_ARTIFACT_EXT:
        java_request_hits = _count_groups([
            ("servlet_api", r"javax[/\.]servlet|HttpServletRequest|HttpServletResponse|javax[/\.]servlet[/\.]jsp|_jspService|JspWriter"),
            ("request_access", r"getParameter|getHeader|getInputStream|getReader|getParameterMap|ServletInputStream"),
            ("response_access", r"getWriter|ServletOutputStream|setContentType|sendRedirect"),
        ], text)
        java_exec_hits = []
        if _java_has_tokens(text, ("java/lang/Runtime", "getRuntime", "exec")) or _has(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec", text):
            java_exec_hits.append("runtime_exec")
        if _has(r"ProcessBuilder|cmd\.exe|/bin/sh|powershell", text):
            java_exec_hits.append("process_builder_or_shell")
        java_loader_hits = _count_groups([
            ("define_class", r"defineClass"),
            ("classloader", r"ClassLoader"),
            ("reflection", r"getDeclaredMethod|getMethod|invoke"),
            ("class_for_name", r"Class\.forName|forName"),
        ], text)
        java_capability_hits = _count_groups([
            ("file_io", r"java[/\.]io[/\.]File|FileOutputStream|FileInputStream|RandomAccessFile"),
            ("database", r"java[/\.]sql|DriverManager|getConnection|PreparedStatement|ResultSet"),
            ("network", r"java[/\.]net[/\.](?:Socket|URL|URLConnection)|URLConnection|Socket"),
            ("upload_download", r"FileUpload|upload|download|Content-Disposition"),
        ], text)
        java_markers = _count_groups([
            ("behinder_payload", r"net[/\.]rebeyond[/\.]behinder[/\.]payload[/\.]java"),
            ("chopper_family", r"Chopper|Chropper|caidao|cknife|(?:^|[^A-Za-z0-9_])(?:asenc|asoutput|7!I6)(?:[^A-Za-z0-9_]|$)"),
            ("known_webshell_class", r"(?:^|[/.$_])(?:Cmd|CmdServlet|CmdShell|ConnectBack|GetShell|Evaluate|Database|BShell|BasicInfo|FileOperation|browser_jsp|Agent_[0-9]+)(?:$|[/.$_])"),
            ("webshell_terms", r"webshell|cmdshell|backshell"),
        ], base_name + "\n" + text[:8192])

        java_context = bool(java_request_hits)
        if java_context and "behinder_payload" in java_markers:
            score = max(score, 75)
            reasons.append("java_behinder_payload")
        elif java_context and java_exec_hits and java_markers:
            score = max(score, 75)
            reasons.append("java_named_request_to_exec")
        elif java_context and java_loader_hits and len(java_capability_hits) >= 2 and java_markers:
            score = max(score, 65)
            reasons.append("java_named_request_to_loader")
        elif (
            java_context
            and java_exec_hits
            and java_loader_hits
            and len(java_capability_hits) >= 3
            and len(file_data) <= int(policy.get("webshell_capability_java_compact_max_bytes", 32768))
        ):
            score = max(score, 65)
            reasons.append("java_compact_multi_capability")

        if score < int(policy.get("webshell_capability_min_subscore", 30)):
            return 0, None
        if paranoid:
            score += int(policy.get("webshell_capability_paranoid_boost", 10))
        score = min(score, int(policy.get("webshell_capability_max_subscore", 85)))
        reasons.append("java=%s/%s/%s/%s" % (
            "|".join(java_request_hits[:2]) or "-",
            "|".join(java_exec_hits[:2]) or "-",
            "|".join(java_loader_hits[:2]) or "-",
            "|".join((java_markers + java_capability_hits)[:4]) or "-",
        ))
        detail = "platform=%s %s" % (ext.lstrip(".") or "java", ",".join(reasons[:6]))
        return score, "Heuristic WebshellCapability SUBSCORE: %s DESC: %s" % (score, detail)

    markers = _count_groups([
        ("antsword", r"antsword|asenc|asoutput|ant\s*剑"),
        ("caidao_chopper", r"caidao|chopper|cknife|c9999|菜刀|中国菜刀|landgrey"),
        ("webshell_name", r"web\s*shell|webshell|cmdshell|back\s*shell|backshell|portmap|fileoperation|basicinfo|webshellmodule|(?:^|[^a-z0-9])(?:c99|c9999|b374k|wso|r57|p0wny)(?:[^a-z0-9]|$)|小马|大马|后门|提权|一句话"),
    ], base_name + "\n" + text[:8192])
    filename_markers = _count_groups([
        ("webshell_filename", r"(?:^|[/_.-])(?:cmd|command|shell|database|bypass|udf|servu|fileoperation|basicinfo)(?:$|[/_.-])"),
    ], base_name)
    markers.extend([hit for hit in filename_markers if hit not in markers])
    if markers:
        score += 15
        reasons.append("marker=%s" % "|".join(markers[:3]))

    entry_hits = _count_groups([
        ("main_entry", r"\bfunction\s+main\s*\(|\bsub\s+main\b|\bvoid\s+main\s*\("),
        ("request_entry", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$HTTP_(?:GET|POST|COOKIE|SERVER|POST_FILES)_VARS\b|Request\s*[\[.]|request\s*\.\s*get|Form\.|Url\.|Func::postVar\s*\(|\bpostVar\s*\(|getallheaders\s*\(|apache_request_headers\s*\(|\bget\s*\(\s*['\"][A-Za-z0-9_:-]+['\"]\s*\)"),
        ("server_page", r"<%@?\s*page|<%|<jsp:(?:root|scriptlet|declaration|expression)\b|<cf(?:script|set|try|switch|case|file|directory)\b|runat\s*=\s*['\"]server"),
        ("variable_dispatch", r"\$\$[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*\s*\([^)]{0,80}\)|\([^)]{0,120}\)\s*\([^)]{0,120}\)|call_user_func\s*\("),
        ("form_control", r"txtSql\.Text|txtConnection\.Text|TextBox|textarea\s+name\s*=|input\s+name\s*="),
    ], text)
    if entry_hits:
        score += 15
        reasons.append("entry=%s" % "|".join(entry_hits[:3]))

    capability_hits = _count_groups([
        ("command_exec", r"\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(|runShell\s*\(|['\"]sysatem['\"]|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|ProcessStartInfo|Process\s*\.\s*Start|WScript\.Shell|cfexecute\b"),
        ("file_manager", r"\b(?:fopen|fwrite|fread|file_get_contents|file_put_contents|unlink|chmod|mkdir|rmdir|rename|copy|scandir|readdir|opendir|move_uploaded_file)\s*\(|ZipArchive|ADODB\.Stream|Scripting\.FileSystemObject|Server\.MapPath|CFFILE\b|CFDIRECTORY\b|java\.io\.File|FileStream|StreamWriter"),
        ("database_client", r"\b(?:mysqli?_connect|mysqli?_query|mysql_query|pg_connect|sqlite|PDO\s*\(|sqlsrv_|oci_connect)\b|ADODB\.Connection|java\.sql\.|DriverManager\.getConnection|cfquery\b|SqlConnection|SqlCommand|ExecuteReader|ConnectionString|txtSql\.Text|txtConnection\.Text"),
        ("network_proxy", r"\b(?:socket_create|socket_connect|socket_bind|socket_listen|fsockopen|pfsockopen|stream_socket_client|curl_exec)\s*\(|java\.net\.(?:Socket|URL|HttpURLConnection)|openConnection\s*\(|AsynchronousSocketChannel|InetSocketAddress|TcpClient|System\.Net\.Sockets|MSXML2\.ServerXMLHTTP|ServerXMLHTTP|WinHttp\.WinHttpRequest|XMLHTTP|CFHTTP\b"),
        ("dynamic_loader", r"\b(?:eval|assert|create_function)\b|['\"]asser['\"]|['\"]as['\"]\s*\.\s*['\"]sert|substr\s*\([^)]{0,100}\)\s*\.\s*substr\s*\(|preg_replace\s*\([^;]{0,200}/[a-z]*e[a-z]*|ClassLoader|defineClass|Assembly\.Load|GetType\s*\(|InvokeMember\s*\(|Execute\s*\(|Eval\s*\("),
        ("upload_download", r"Request\.Files|FileUpload|SaveAs\s*\(|move_uploaded_file\s*\(|readbinary|Response\.BinaryWrite|Content-Disposition|download"),
        ("runtime_introspection", r"php_uname\s*\(|ini_get\s*\(\s*['\"]disable_functions|debug_backtrace\s*\(|getTrace\s*\(|parse_elf\s*\(|proc/self/maps|zif_system|open_basedir|COM\s*\(\s*['\"]IIS://"),
    ], text)
    if capability_hits:
        weights = {
            "command_exec": 35,
            "file_manager": 25,
            "database_client": 20,
            "network_proxy": 25,
            "dynamic_loader": 30,
            "upload_download": 20,
            "runtime_introspection": 20,
        }
        score += sum(weights.get(h, 15) for h in capability_hits[:4])
        reasons.append("capability=%s" % "|".join(capability_hits[:5]))

    protocol_hits = _count_groups([
        ("auth_or_password", r"\b(?:password|passwd|pwd|pass|auth|login|token|secret)\b|Pwd\s*="),
        ("webshell_framing", r"\\x37\\x21\\x49\\x36|7!I6|asoutput|asenc|chopper|Form\.chopper|status[\"']?\s*[:=]\s*[\"']success"),
        ("encoding_channel", r"base64(?:_decode|encode)?|bin\.base64|Chr\s*\(\s*9\s*\)|getBytes\s*\("),
        ("percent_encoded_script", r"%3cscript|%253cscript|document\.write\s*\(\s*unescape|(?:%25(?:5c)?u[0-9a-fA-F]{4}){3,}"),
    ], text)
    if protocol_hits:
        score += 10 + min(15, 5 * len(protocol_hits))
        reasons.append("protocol=%s" % "|".join(protocol_hits[:3]))

    pure_file_transfer = (
        ext in _PHP_EXT
        and capability_hits
        and set(capability_hits).issubset({"file_manager", "upload_download"})
        and not markers
        and not protocol_hits
    )
    if pure_file_transfer and _has(r"\bmove_uploaded_file\s*\(", text):
        has_upload_allowlist = _has(
            r"\b(?:in_array\s*\(|pathinfo\s*\(|getimagesize\s*\(|mime_content_type\s*\(|finfo_file\s*\()",
            text,
        ) and _has(r"\b(?:jpg|jpeg|png|gif|webp|pdf|txt|csv)\b", text)
        if has_upload_allowlist and not _has(
            r"\b(?:eval|assert|system|shell_exec|passthru|proc_open|popen|exec|base64_decode|gzinflate|gzdecode|str_rot13|strrev|preg_replace)\s*\(",
            text,
        ):
            return 0, None

    if _has(r"(?:^|[^a-z0-9])(?:proxy|wsproxy|websphereproxy|socks|tunnel)(?:[^a-z0-9]|$)", base_name) and "network_proxy" in capability_hits:
        score = max(score, 55)
        reasons.append("named_network_proxy")
    if _has(r"filemanager|file_manager", base_name) and ("file_manager" in capability_hits or "upload_download" in capability_hits):
        score = max(score, 45)
        reasons.append("named_file_manager")

    if ext in _PHP_EXT and _has(r"ReflectionClass\s*\(", text) and _has(r"\$_(?:POST|REQUEST|GET)|\$\$_", text):
        score = max(score, 70)
        reasons.append("php_reflection_dispatch")
    if ext in _PHP_EXT and _has(_PHP_SOURCE_RE, text) and _has(r"['\"]sysatem['\"]|['\"]asser['\"]|['\"]sert['\"]|['\"]as['\"]\s*\.\s*['\"]sert|substr\s*\([^)]{0,100}\)\s*\.\s*substr\s*\(", text):
        score = max(score, 70)
        reasons.append("php_reconstructed_sink")
    if ext in _PHP_EXT and _has(r"\bZend\b.{0,80}200[0-9]{7}", text[:512]):
        score = max(score, 45 if markers else 35)
        reasons.append("encoded_php_zend")
    if ext in _PHP_EXT:
        bitwise_assignments = len(re.findall(
            r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;\n]{0,180}(?:\^|\||&)[^;\n]{0,180};",
            text,
            re.IGNORECASE,
        ))
        if bitwise_assignments >= 8 and (_has(r"\bUnknown[_-]|/quarantine|/quarantines", path_lower) or _has(r"\$\w+\s*\(", text)):
            score = max(score, 55)
            reasons.append("php_dense_bitwise_obfuscation=%s" % bitwise_assignments)
        if _has(r"preg_replace\s*\([^;]{0,200}/[a-z]*e[a-z]*", text) and _has(r"\\x[0-9a-fA-F]{1,2}|str_rot13|base64|strrev", text):
            score = max(score, 70)
            reasons.append("php_preg_replace_e_obfuscation")
        if _has(r"preg_replace\s*\(", text) and len(re.findall(r"\bchr\s*\(", text, re.IGNORECASE)) >= 16 and _has(r"pwd\s*=|0x65\)\s*\.\s*chr\s*\(\s*0x76|chr\s*\(\s*0x40\s*\)\s*\.\s*chr\s*\(\s*0x65", text):
            score = max(score, 70)
            reasons.append("php_chr_preg_replace_eval")
        if _has(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*['\"]/[^'\"]{0,160}/[a-z]*e['\"]", text) and _has(r"\\x[0-9a-fA-F]{1,2}|str_rot13|base64|strrev", text):
            score = max(score, 70)
            reasons.append("php_variable_preg_replace_e")
        if _has(r"str_rot13\s*\(\s*['\"]onfr64_qrpbqr|str_rot13\s*\(\s*['\"]tmvasyngr|md5_pass\s*=", text) and _has(r"strrev\s*\(|[A-Za-z0-9+/]{80,}", text):
            score = max(score, 75)
            reasons.append("php_rot13_encoded_payload")
        if _has(r"\$Remote_server\s*=\s*['\"]https?://|file_get_contents\s*\([^;]{0,120}https?://|stream_context_create\s*\(", text) and _has(r"\$_SERVER\s*\[|PHP_SELF|SERVER_NAME|echo\s+\$Content", text):
            score = max(score, 60)
            reasons.append("php_remote_loader")
        if _has(r"ZipArchive|f0bad2Zip|compressDestFile|compressSrcDir|unCompress", text) and _has(r"\bget\s*\(\s*['\"][A-Za-z0-9_:-]+['\"]\s*\)|opendir\s*\(|readdir\s*\(", text):
            score = max(score, 55)
            reasons.append("php_webshell_zip_module")
        if _has(r"runShell\s*\(\s*Func::postVar\s*\(|execAction\s*\(", text):
            score = max(score, 65)
            reasons.append("php_controller_runshell")
        if _has(r"fileStart\s*=\s*['\"].{0,120}404 Not Found|Header\s*\(\s*['\"]HTTP/1\.1 404 Not Found", text) and _has(r"Crypt_AES|encrypt\s*\(|decrypt\s*\(|data\.php", text):
            score = max(score, 55)
            reasons.append("php_hidden_encrypted_store")
        if _has(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"][0-9]{1,20}(?:-[0-9]{1,24}){40,}", text) and _has(r"\beval\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)", text) and _has(r"\b(?:chr|hexdec|base_convert|rawurldecode|urldecode|array_reverse|strrev)\s*\(", text):
            score = max(score, 70)
            reasons.append("php_numeric_encoded_eval_payload")
    if ext in _PHP_EXT and _has(r"\bfunction\s+main\s*\([^)]{0,160}\$(?:cmd|command|sql|path|file|action|target|host|port)", text) and capability_hits:
        score = max(score, 60)
        reasons.append("php_plugin_main")
    if ext in _PHP_EXT and _has(r"web\s*shell|console commands from your browser|Yii::setPathOfAlias\s*\(\s*['\"]webshell", text):
        score = max(score, 65)
        reasons.append("php_declared_webshell_module")
    if ext in _PHP_EXT and _has(r"C9999Shell|Source:\s*C9999Shell|document\.write\s*\(\s*unescape|%253cscript", text):
        score = max(score, 60)
        reasons.append("php_percent_encoded_shell")
    if ext in _PHP_EXT and _has(r"@?\s*include(?:_once)?\s*(?:\(|\s)\s*['\"][^'\"]*(?:\\x[0-9a-fA-F]{2}[^'\"]*){3,}['\"]", text):
        score = max(score, 55)
        reasons.append("php_hex_escaped_include")
    if ext in _PHP_EXT and _has(r"\breadfile\s*\(\s*\$VAR\s*\[\s*['\"](?:file|path|url)['\"]\s*\]\s*\)", text):
        score = max(score, 40)
        reasons.append("php_var_readfile_download")
    if ext in _PHP_EXT and _has(r"enable_functions\s+enumeration|get_cfg_var\s*\(\s*['\"]disable_functions|disable_functions\s+none", text) and _has(r"\b(?:exec|passthru|shell_exec|system|proc_open|popen|stream_socket_client|fsockopen)\b", text):
        score = max(score, 40)
        reasons.append("php_dangerous_function_inventory")
    if ext in _PHP_EXT and _has(r"exif_read_data\s*\(", text) and _has(r"preg_replace\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\[\s*['\"](?:Model|Make)['\"]", text):
        score = max(score, 45)
        reasons.append("php_exif_preg_replace_vector")
    if ext in _PHP_EXT and _has(r"execCode|executeCode\s*\(|命令执行", text) and _has(r"DataTransport|Access-Control-Allow-Origin", text) and _has(r"(^|[/_\\.-])exec(?:[_\\.-]|$)", path_lower):
        score = max(score, 45)
        reasons.append("php_command_ui_module")
    if ext in _JSP_EXT and _has(r"(?:\\u[0-9a-fA-F]{4}){6,}", text) and _has(r"java\.(?:io|sql|net)|Pwd|request|Connection", text):
        score = max(score, 65)
        reasons.append("jsp_unicode_encoded_webshell")
    if ext in _JSP_EXT and _has(r"<jsp:(?:root|declaration|scriptlet)\b", text) and _has(r"\{(?:globalCode|code)\}", text):
        score = max(score, 45)
        reasons.append("jspx_code_template")
    if ext in _ASPNET_EXT and _has(r"StreamWriter\s*\(\s*Server\.MapPath|Request\.Item|Request\.Files|ProcessStartInfo|WScript\.Shell", text):
        score = max(score, 60)
        reasons.append("aspnet_dropper_or_exec")
    if ext in _ASPNET_EXT and _has(r"SqlCommand|SqlConnection|ExecuteReader|txtSql\.Text|txtConnection\.Text", text) and _has(r"runat\s*=\s*['\"]server|<%@\s*Page", text):
        score = max(score, 60)
        reasons.append("aspnet_sql_console")
    if ext in _ASPNET_EXT and _has(r"System\.Security\.AccessControl|System\.Management|ACL Searcher|ValidateRequest\s*=\s*['\"]false|EnableViewStateMac\s*=\s*['\"]false", text) and _has(r"DirectoryInfo|FileInfo|GetAccessRules|runat\s*=\s*['\"]server|<%@\s*Page", text):
        score = max(score, 45)
        reasons.append("aspnet_acl_admin_console")
    if ext == ".asp" and _has(r"server\.scripttimeout|Response\.Buffer|On Error Resume Next", text) and (_has(r"Array\s*\(", text) or markers):
        score = max(score, 45)
        reasons.append("classic_asp_obfuscated_admin")
    if ext == ".asp" and _has(r"wsh\.regread|WScript\.Shell", text) and _has(r"Terminal Server|WinStations|PortNumber|HKEY_LOCAL_MACHINE", text):
        score = max(score, 45)
        reasons.append("classic_asp_registry_admin")
    if ext in _CFM_EXT and _has(r"Form\.chopper|<CFSWITCH|<CFFILE|<CFDIRECTORY|CreateObject\s*\(\s*['\"]java", text):
        score = max(score, 70)
        reasons.append("cfm_chopper_capabilities")
    if ext in _SCRIPT_EXT and _has(r"\b(?:socket|bind|listen|accept|exec|system|fork)\b", text) and _has(r"\b(?:perl|cgi|backdoor|shell|cmd)\b|#!/", text):
        score = max(score, 45)
        reasons.append("cgi_perl_shell_capability")

    dangerous_count = len(capability_hits)
    has_context = bool(entry_hits or protocol_hits or markers)
    if dangerous_count >= 2 and has_context:
        score = max(score, 45)
    elif dangerous_count >= 1 and (entry_hits and protocol_hits):
        score = max(score, 35)
    elif score < int(policy.get("webshell_capability_min_subscore", 30)):
        return 0, None

    if paranoid:
        score += int(policy.get("webshell_capability_paranoid_boost", 10))

    score = min(score, int(policy.get("webshell_capability_max_subscore", 85)))
    detail = "platform=%s %s" % (ext.lstrip(".") or "unknown", ",".join(reasons[:6]))
    return score, "Heuristic WebshellCapability SUBSCORE: %s DESC: %s" % (score, detail)
