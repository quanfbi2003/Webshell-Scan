#!/usr/bin/env python3
import argparse
import shutil
import signal as signal_module
import stat
from bisect import bisect_left
from collections import Counter
from sys import platform as _platform
import yara  # install 'yara-python' module not the outdated 'yara' module
from libs.helpers import *
from libs.levenshtein import *
from libs.logger import *

# For Windows
try:
    import wmi
    from win32comext.shell import shell
except:
    pass

# Version
VERSION = "v1.5"

# Platform
os_platform = ""

if _platform == "win32":
    os_platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

# Predefined Evil Extensions
EVIL_EXTENSIONS = [".vbs", ".ps", ".ps1", ".rar", ".tmp", ".bas", ".bat", ".chm", ".cmd", ".com", ".cpl",
                   ".crt", ".dll", ".exe", ".hta", ".js", ".lnk", ".msc", ".ocx", ".pcd", ".pif", ".pot", ".pdf",
                   ".reg", ".scr", ".sct", ".sys", ".url", ".vb", ".vbe", ".wsc", ".wsf", ".wsh", ".ct", ".t",
                   ".input", ".war", ".jsp", ".jspx", ".php", ".asp", ".aspx", ".doc", ".docx", ".pdf", ".xls", ".xlsx",
                   ".ppt",
                   ".pptx", ".tmp", ".log", ".dump", ".pwd", ".w", ".txt", ".conf", ".cfg", ".conf", ".config", ".psd1",
                   ".psm1", ".ps1xml", ".clixml", ".psc1", ".pssc", ".pl", ".www", ".rdp", ".jar", ".docm", ".sys"]

ALLOW_EXTENTIONS = [".asp", ".vbs", ".ps1", ".bas", ".bat", ".vb", ".vbe", ".wsc", ".wsf",
                    ".wsh", ".jsp", ".jspx", ".php", ".asp", ".aspx", ".psd1", ".psm1", ".ps1xml", ".clixml", ".psc1",
                    ".pssc", ".pl"]

SCRIPT_EXTENSIONS = [".asp", ".vbs", ".ps1", ".bas", ".bat", ".js", ".vb", ".vbe", ".wsc", ".wsf",
                     ".wsh", ".jsp", ".jspx", ".php", ".asp", ".aspx", ".psd1", ".psm1", ".ps1xml", ".clixml", ".psc1",
                     ".pssc", ".pl"]

SCRIPT_TYPES = ["VBS", "PHP", "JSP", "ASP", "BATCH"]

# Mode
FULL_SCAN = False


def ioc_contains(sorted_list, value):
    # returns true if sorted_list contains value
    index = bisect_left(sorted_list, value)
    return index != len(sorted_list) and sorted_list[index] == value


def get_string_matches(strings):
    try:
        string_matches = []
        matching_strings = ""
        for estring in strings:
            # print string
            extract = estring[2]
            if not extract in string_matches:
                string_matches.append(extract)

        string_num = 1
        for estring in string_matches:
            matching_strings += " Str" + str(string_num) + ": " + removeNonAscii(estring)
            string_num += 1

        # Limit string
        if len(matching_strings) > 140:
            matching_strings = matching_strings[:140] + " ... (truncated)"

        return matching_strings.lstrip(" ")
    except Exception:
        traceback.print_exc()


def get_file_data(filePath):
    fileData = b''
    try:
        # Read file complete
        with open(filePath, 'rb') as f:
            fileData = f.read()
    except Exception:
        # logger.log("ERROR", "FileScan", "Cannot open file %s (access denied)" % filePath)
        pass
    finally:
        return fileData


def script_stats_analysis(data):
    """
    Only in Full Scan!!!
    Doing a statistical analysis for scripts like PHP, JavaScript or PowerShell to
    detect obfuscated code
    :param data:
    :return: message, score
    """

    anomal_chars = [r'^', r'{', r'}', r'"', r',', r'<', r'>', ';']
    anomal_char_stats = {}
    char_stats = {"upper": 0, "lower": 0, "numbers": 0, "symbols": 0, "spaces": 0}
    anomalies = []
    c = Counter(data)
    anomaly_score = 0

    # Check the characters
    for char in c.most_common():
        if chr(char[0]) in anomal_chars:
            anomal_char_stats[char[0]] = char[1]
        if chr(char[0]).isupper():
            char_stats["upper"] += char[1]
        elif chr(char[0]).islower():
            char_stats["lower"] += char[1]
        elif chr(char[0]).isdigit():
            char_stats["numbers"] += char[1]
        elif chr(char[0]).isspace():
            char_stats["spaces"] += char[1]
        else:
            char_stats["symbols"] += char[1]

    # Totals
    char_stats["total"] = len(data)
    char_stats["alpha"] = char_stats["upper"] + char_stats["lower"]

    # Detect Anomalies
    if char_stats["alpha"] > 40 and char_stats["upper"] > (char_stats["lower"] * 0.9):
        anomalies.append("upper to lower ratio")
        anomaly_score += 20
    if char_stats["symbols"] > char_stats["alpha"]:
        anomalies.append("more symbols than alphanum chars")
        anomaly_score += 40
    for ac, count in iter(anomal_char_stats.items()):
        if (count / char_stats["alpha"]) > 0.05:
            anomalies.append("symbol count of '%s' very high" % ac)
            anomaly_score += 40

    # Generate message
    message = "Anomaly detected ANOMALIES: '{0}'".format("', '".join(anomalies))
    if anomaly_score >= 40:
        return message, anomaly_score

    return "", 0


class Scanner(object):
    # Signatures
    yara_rules = []
    filename_iocs = []
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    false_hashes = {}
    c2_server = {}

    # Yara rule directories
    yara_rule_directories = []

    # Excludes (list of regex that match within the whole path) (user-defined via excludes.cfg)
    fullExcludes = []
    # Platform specific excludes (match the beginning of the full path) (not user-defined)
    startExcludes = []

    # File type magics
    filetype_magics = {}
    max_filetype_magics = 0

    # Predefined paths to skip (Linux platform)
    LINUX_PATH_SKIPS_START = {"/proc", "/dev", "/sys/kernel/debug", "/sys/kernel/slab", "/sys/devices",
                              "/usr/src/linux"}
    MOUNTED_DEVICES = {"/media", "/volumes"}
    LINUX_PATH_SKIPS_END = {"/initctl"}

    def __init__(self, ):
        # Get application path
        self.app_path = get_application_path()

        # Check if signature database is present
        sig_dir = os.path.join(self.app_path, "libs/signature-base".replace("/", os.sep))
        if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
            logger.log("NOTICE", "Init", "The 'signature-base' subdirectory doesn't exist or is empty. "
                                         "Trying to retrieve the signature database automatically.")
            sys.exit(1)

        # Excludes
        self.initialize_excludes(os.path.join(self.app_path, "config/excludes.cfg".replace("/", os.sep)))

        # Linux static excludes
        if not args.force and os_platform == "linux":
            self.startExcludes = self.LINUX_PATH_SKIPS_START | self.MOUNTED_DEVICES

        # Set IOC path
        self.ioc_path = os.path.join(self.app_path, "libs/signature-base/iocs/".replace("/", os.sep))

        # Yara rule directories
        self.yara_rule_directories.append(os.path.join(self.app_path, "libs/signature-base/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(os.path.join(self.app_path, "libs/signature-base/iocs/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(os.path.join(self.app_path, "libs/signature-base/3rdparty".replace("/", os.sep)))

        # Read IOCs -------------------------------------------------------
        # File Name IOCs (all files in iocs that contain 'filename')
        self.initialize_filename_iocs(self.ioc_path)
        logger.log("INFO", "Init",
                   "File Name Characteristics initialized with %s regex patterns" % len(self.filename_iocs))

        # C2 based IOCs (all files in iocs that contain 'c2')
        self.initialize_c2_iocs(self.ioc_path)
        logger.log("INFO", "Init", "C2 server indicators initialized with %s elements" % len(self.c2_server.keys()))

        ## Hash based IOCs (all files in iocs that contain 'hash')
        self.initialize_hash_iocs(self.ioc_path)
        logger.log("INFO", "Init", "Malicious MD5 Hashes initialized with %s hashes" % len(self.hashes_md5.keys()))
        logger.log("INFO", "Init", "Malicious SHA1 Hashes initialized with %s hashes" % len(self.hashes_sha1.keys()))
        logger.log("INFO", "Init", "Malicious SHA256 Hashes initialized with %s hashes"
                   % len(self.hashes_sha256.keys()))

        # Hash based False Positives (all files in iocs that contain 'hash' and 'falsepositive')
        self.initialize_hash_iocs(self.ioc_path, false_positive=True)
        logger.log("INFO", "Init", "False Positive Hashes initialized with %s hashes" % len(self.false_hashes.keys()))

        # Compile Yara Rules
        self.initialize_yara_rules()

        # Initialize File Type Magic signatures
        self.initialize_filetype_magics(os.path.join(self.app_path, 'libs/signature-base/misc/file-type-signatures.txt'
                                                     .replace("/", os.sep)))

        # Levenshtein Checker
        self.LevCheck = LevCheck()

    def scan_path(self, path):
        global MESSAGE
        MESSAGE = []
        # Check if path exists
        if not os.path.exists(path):
            logger.log("ERROR", "FileScan", "None Existing Scanning Path %s ...  " % path)
            return

        # Startup
        logger.log("INFO", "FileScan", "Scanning Path %s ...  " % path)
        # Platform specific excludes
        for skip in self.startExcludes:
            if path.startswith(skip):
                logger.log("INFO", "FileScan",
                           "Skipping %s directory [fixed excludes] (try using --force)" % skip)
                return

        # Counter
        c = 0
        total = 0

        for root, directories, files in os.walk(path, onerror=walk_error, followlinks=False):
            # Skip paths that start with ..
            newDirectories = []
            for directory in directories:
                skipIt = False

                # Generate a complete path for comparisons
                completePath = os.path.join(root, directory).lower() + os.sep

                # Platform specific excludes
                for skip in self.startExcludes:
                    if completePath.startswith(skip):
                        skipIt = True

                if not skipIt:
                    newDirectories.append(directory)
            directories[:] = newDirectories

            total += len(files)

            # Loop through files
            for filename in files:
                try:
                    # Findings
                    reasons = []
                    # Total Score
                    total_score = 0

                    # Get the file and path
                    filePath = os.path.join(root, filename)
                    fpath = os.path.split(filePath)[0]
                    # Clean the values for YARA matching
                    # > due to errors when Unicode characters are passed to the match function as
                    #   external variables
                    filePathCleaned = fpath.encode('ascii', errors='replace')
                    fileNameCleaned = filename.encode('ascii', errors='replace')

                    # Get Extension
                    extension = os.path.splitext(filePath)[1].lower()
                    # if not any(x for x in ALLOW_EXTENTIONS if extension == x):
                    #     continue
                    #     pass
                    # Skip marker
                    skipIt = False

                    # Unicode error test
                    # if 1 > 0:
                    #    walk_error(OSError("[Error 3] No such file or directory"))

                    # User defined excludes
                    for skip in self.fullExcludes:
                        if skip.search(filePath):
                            skipIt = True

                    # Linux directory skip
                    if os_platform == "linux" or os_platform == "macos":

                        # Skip paths that end with ..
                        for skip in self.LINUX_PATH_SKIPS_END:
                            if filePath.endswith(skip):
                                if self.LINUX_PATH_SKIPS_END[skip] == 0:
                                    self.LINUX_PATH_SKIPS_END[skip] = 1
                                    skipIt = True

                        # File mode
                        mode = os.stat(filePath).st_mode
                        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(
                                mode) or stat.S_ISSOCK(mode):
                            continue

                    # Skip
                    if skipIt:
                        continue

                    # Counter
                    c += 1

                    print_progress(c, total)

                    # Skip program directory
                    # print appPath.lower() +" - "+ filePath.lower()
                    if self.app_path.lower() in filePath.lower():
                        continue

                    # File Name Checks -------------------------------------------------
                    for fioc in self.filename_iocs:
                        match = fioc['regex'].search(filePath)
                        if match:
                            # Check for False Positive
                            if fioc['regex_fp']:
                                match_fp = fioc['regex_fp'].search(filePath)
                                if match_fp:
                                    continue
                            # Create Reason
                            reasons.append("File Name IOC matched PATTERN: %s SUBSCORE: %s DESC: %s" % (
                                fioc['regex'].pattern, fioc['score'], fioc['description']))
                            total_score += int(fioc['score'])

                    # Levenshtein Check
                    result = check(filename)
                    if result:
                        reasons.append("Levenshtein check - filename looks much like a well-known system file "
                                       "SUBSCORE: 40 ORIGINAL: %s" % result)
                        total_score += 60

                    # Evaluate Type
                    fileType = get_file_type(filePath, self.filetype_magics, self.max_filetype_magics, logger)

                    # Hash Check -------------------------------------------------------
                    # Do the check

                    # Set fileData to an empty value
                    fileData = ""

                    fileData = get_file_data(filePath)

                    # First bytes
                    firstBytesString = "%s / %s" % (fileData[:20].hex(), removeNonAsciiDrop(fileData[:20]))

                    # Hash Eval
                    matchType = None
                    matchDesc = None
                    matchHash = None
                    md5 = 0
                    sha1 = 0
                    sha256 = 0

                    md5, sha1, sha256 = generateHashes(fileData)
                    md5_num = int(md5, 16)
                    sha1_num = int(sha1, 16)
                    sha256_num = int(sha256, 16)

                    # False Positive Hash
                    if md5_num in self.false_hashes.keys() or sha1_num in self.false_hashes.keys() or sha256_num \
                            in self.false_hashes.keys():
                        continue

                    # Malware Hash
                    if ioc_contains(self.hashes_md5_list, md5_num):
                        matchType = "MD5"
                        matchDesc = self.hashes_md5[md5_num]
                        matchHash = md5
                    if ioc_contains(self.hashes_sha1_list, sha1_num):
                        matchType = "SHA1"
                        matchDesc = self.hashes_sha1[sha1_num]
                        matchHash = sha1
                    if ioc_contains(self.hashes_sha256_list, sha256_num):
                        matchType = "SHA256"
                        matchDesc = self.hashes_sha256[sha256_num]
                        matchHash = sha256

                    # Hash string
                    if matchType:
                        reasons.append("Malware Hash TYPE: %s HASH: %s SUBSCORE: 100 DESC: %s" % (
                            matchType, matchHash, matchDesc))
                        total_score += 100

                    # Script Anomalies Check
                    if FULL_SCAN and (extension in SCRIPT_EXTENSIONS or type in SCRIPT_TYPES):
                        message, score = script_stats_analysis(fileData)
                        if message:
                            reasons.append("%s SCORE: %s" % (message, score))
                            total_score += score

                    # Yara Check -------------------------------------------------------

                    # Scan the read data
                    try:
                        for (score, rule, description, reference, matched_strings, author) in \
                                self.scan_data(fileData=fileData,
                                               fileType=fileType,
                                               fileName=fileNameCleaned,
                                               filePath=filePathCleaned,
                                               extension=extension,
                                               md5=md5  # legacy rule support
                                               ):
                            # Message
                            message = "Yara Rule MATCH: %s SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s" % \
                                      (rule, score, description, reference, author)
                            # Matches
                            if matched_strings:
                                message += " MATCHES: %s" % matched_strings

                            total_score += score
                            reasons.append(message)

                    except Exception:
                        logger.log("ERROR", "FileScan", "Cannot YARA scan file: %s" % filePathCleaned)

                    # Info Line -----------------------------------------------------------------------
                    fileInfo = "===========================================================\n" \
                               "FILE: %s\n SCORE: %s%s\n " % (
                        filePath, total_score, getAgeString(filePath))
                    message_type = "INFO"
                    # Now print the total result
                    if total_score >= 100:
                        message_type = "ALERT"
                    elif total_score >= 60:
                        message_type = "WARNING"
                    elif total_score >= 40:
                        message_type = "NOTICE"

                    if total_score < 40:
                        continue

                    # Reasons to message body
                    message_body = fileInfo
                    for i, r in enumerate(reasons):
                        message_body += "\tREASON_{0}: {1}\n ".format(i + 1, r)
                    if args.quarantine and "Yara Rule" in message_body:
                        src = filePath
                        filename = os.path.basename(filePath.replace("/", os.sep)) + "." + str(int(time.time()))
                        dst = os.path.join(self.app_path, ("quarantine/" + filename).replace("/", os.sep))
                        try:
                            shutil.move(src, dst)
                            message_body += "FILE MOVED TO QUARANTINE: %s\n " % dst
                        except Exception:
                            message_body += "FILE CAN NOT MOVED TO QUARANTINE!!!\n "
                    MESSAGE.append([total_score, message_type, message_body])
                except Exception:
                    pass
        MESSAGE.sort(key=lambda x: x[0], reverse=True)
        for i in MESSAGE:
            logger.log(i[1], "FileScan", i[2])

    def scan_data(self, fileData, fileType="-", fileName=b"-", filePath=b"-", extension=b"-", md5="-"):

        # Scan parameters
        # print fileType, fileName, filePath, extension, md5
        # Scan with yara
        try:
            for rules in self.yara_rules:
                # Yara Rule Match
                matches = rules.match(data=fileData,
                                      externals={
                                          'filename': fileName.decode('utf-8'),
                                          'filepath': filePath.decode('utf-8'),
                                          'extension': extension,
                                          'filetype': fileType,
                                          'md5': md5,
                                          'owner': "dummy"
                                      })

                # If matched
                if matches:
                    for match in matches:

                        score = 70
                        description = "not set"
                        reference = "-"
                        author = "-"

                        # Built-in rules have meta fields (cannot be expected from custom rules)
                        if hasattr(match, 'meta'):

                            if 'description' in match.meta:
                                description = match.meta['description']
                            if 'cluster' in match.meta:
                                description = "IceWater Cluster {0}".format(match.meta['cluster'])

                            if 'reference' in match.meta:
                                reference = match.meta['reference']
                            if 'viz_url' in match.meta:
                                reference = match.meta['viz_url']
                            if 'author' in match.meta:
                                author = match.meta['author']

                            # If a score is given
                            if 'score' in match.meta:
                                score = int(match.meta['score'])

                        # Matching strings
                        matched_strings = ""
                        if hasattr(match, 'strings'):
                            # Get matching strings
                            matched_strings = get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except Exception:
            pass

    def scan_win_processes(self):
        logger.log("INFO", "Init", "Initializing process scan")
        # WMI Handler
        c = wmi.WMI()
        processes = c.Win32_Process()
        t_systemroot = os.environ['SYSTEMROOT']

        # WinInit PID
        wininit_pid = 0
        # LSASS Counter
        lsass_count = 0

        # App's processes
        app_pid = os.getpid()
        app_ppid = psutil.Process(os.getpid()).ppid()  # safer way to do this - os.ppid() fails in some envs

        for process in processes:
            try:
                # Gather Process Information --------------------------------------
                process_id = process.ProcessId
                name = process.Name
                cmd = process.CommandLine
                if not cmd:
                    cmd = "N/A"
                if not name:
                    name = "N/A"
                path = "none"
                parent_pid = process.ParentProcessId
                priority = process.Priority
                if process.ExecutablePath:
                    path = process.ExecutablePath
                # Owner
                try:
                    owner_raw = process.GetOwner()
                    owner = owner_raw[2]
                except Exception:
                    owner = "unknown"
                if not owner:
                    owner = "unknown"

            except Exception:
                logger.log("ALERT", "ProcessScan",
                           "Error getting all process information. Did you run the scanner 'As Administrator'?")
                continue

            # Is parent to other processes - save PID
            if name == "wininit.exe":
                wininit_pid = process_id

            # Special Checks ------------------------------------------------------
            # better executable path
            if not "\\" in cmd and path != "none":
                cmd = path

            # Process Info
            process_info = "PID: %s NAME: %s OWNER: %s\n CMD: %s\n PATH: %s\n" % (
                str(process_id), name, owner, cmd, path)

            # Skip some PIDs ------------------------------------------------------
            if process_id == 0 or process_id == 4:
                continue

            # Skip own process ----------------------------------------------------
            if app_pid == process_id or app_ppid == process_id:
                continue

            # Skeleton Key Malware Process
            if re.search(r"psexec .* [a-fA-F0-9]{32}", cmd, re.IGNORECASE):
                logger.log("WARNING", "ProcessScan",
                           "Process that looks like SKELETON KEY psexec execution detected %s" % process_info)

            # File Name Checks -------------------------------------------------
            for fioc in self.filename_iocs:
                match = fioc['regex'].search(cmd)
                if match:
                    if fioc['score'] >= 70:
                        logger.log("ALERT", "ProcessScan",
                                   "File Name IOC matched PATTERN: %s\n DESC: %s\n MATCH: %s\n" % (
                                       fioc['regex'].pattern, fioc['description'], cmd))
                    elif fioc['score'] > 40:
                        logger.log("WARNING", "ProcessScan",
                                   "File Name Suspicious IOC matched PATTERN: %s\n DESC: %s\n MATCH: %s\n" % (
                                       fioc['regex'].pattern, fioc['description'], cmd))

            # Suspicious waitfor - possible backdoor https://twitter.com/subTee/status/872274262769500160
            if name == "waitfor.exe":
                logger.log("WARNING", "ProcessScan",
                           "Suspicious waitfor.exe process https://twitter.com/subTee/status/872274262769500160 %s"
                           % process_info)

            ###############################################################
            # THOR Process Connection Checks
            self.check_win_process_connections(process)

            ###############################################################
            # THOR Process Anomaly Checks
            # Source: Sysforensics http://goo.gl/P99QZQ

            # Process: System
            if name == "System" and not process_id == 4:
                logger.log("WARNING", "ProcessScan", "System process without PID=4 %s" % process_info)

            # Process: smss.exe
            if name == "smss.exe" and not parent_pid == 4:
                logger.log("WARNING", "ProcessScan", "smss.exe parent PID is != 4 %s" % process_info)
            if path != "none":
                if name == "smss.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "smss.exe path is not System32 %s" % process_info)
            if name == "smss.exe" and priority != 11:
                logger.log("WARNING", "ProcessScan", "smss.exe priority is not 11 %s" % process_info)

            # Process: csrss.exe
            if path != "none":
                if name == "csrss.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "csrss.exe path is not System32 %s" % process_info)
            if name == "csrss.exe" and priority != 13:
                logger.log("WARNING", "ProcessScan", "csrss.exe priority is not 13 %s" % process_info)

            # Process: wininit.exe
            if path != "none":
                if name == "wininit.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "wininit.exe path is not System32 %s" % process_info)
            if name == "wininit.exe" and priority != 13:
                logger.log("NOTICE", "ProcessScan", "wininit.exe priority is not 13 %s" % process_info)
            # Is parent to other processes - save PID
            if name == "wininit.exe":
                wininit_pid = process_id

            # Process: services.exe
            if path != "none":
                if name == "services.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "services.exe path is not System32 %s" % process_info)
            if name == "services.exe" and priority != 9:
                logger.log("WARNING", "ProcessScan", "services.exe priority is not 9 %s" % process_info)
            if wininit_pid > 0:
                if name == "services.exe" and not parent_pid == wininit_pid:
                    logger.log("WARNING", "ProcessScan",
                               "services.exe parent PID is not the one of wininit.exe %s" % process_info)

            # Process: lsass.exe
            if path != "none":
                if name == "lsass.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "lsass.exe path is not System32 %s" % process_info)
            if name == "lsass.exe" and priority != 9:
                logger.log("WARNING", "ProcessScan", "lsass.exe priority is not 9 %s" % process_info)
            if wininit_pid > 0:
                if name == "lsass.exe" and not parent_pid == wininit_pid:
                    logger.log("WARNING", "ProcessScan",
                               "lsass.exe parent PID is not the one of wininit.exe %s" % process_info)
            # Only a single lsass process is valid - count occurrences
            if name == "lsass.exe":
                lsass_count += 1
                if lsass_count > 1:
                    logger.log("WARNING", "ProcessScan", "lsass.exe count is higher than 1 %s" % process_info)

            # Process: svchost.exe
            if path != "none":
                if name == "svchost.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "svchost.exe path is not System32 %s" % process_info)
            if name == "svchost.exe" and priority != 8:
                logger.log("NOTICE", "ProcessScan", "svchost.exe priority is not 8 %s" % process_info)
            # Windows 10 FP
            # if name == "svchost.exe" and not ( self.check_svchost_owner(owner) or "unistacksvcgroup" in cmd.lower()):
            #    logger.log("WARNING", "ProcessScan", "svchost.exe process owner is suspicious %s" % process_info)

            if name == "svchost.exe" and not " -k " in cmd and cmd != "N/A":
                logger.log("WARNING", "ProcessScan",
                           "svchost.exe process does not contain a -k in its command line %s" % process_info)

            # Process: lsm.exe
            if path != "none":
                if name == "lsm.exe" and not ("system32" in path.lower() or "system32" in cmd.lower()):
                    logger.log("WARNING", "ProcessScan", "lsm.exe path is not System32 %s" % process_info)
            if name == "lsm.exe" and priority != 8:
                logger.log("NOTICE", "ProcessScan", "lsm.exe priority is not 8 %s" % process_info)
            if name == "lsm.exe" and not (
                    owner.startswith("NT ") or owner.startswith("LO") or owner.startswith("SYSTEM")):
                logger.log(u"WARNING", "ProcessScan", "lsm.exe process owner is suspicious %s" % process_info)
            if wininit_pid > 0:
                if name == "lsm.exe" and not parent_pid == wininit_pid:
                    logger.log("WARNING", "ProcessScan",
                               "lsm.exe parent PID is not the one of wininit.exe %s" % process_info)

            # Process: winlogon.exe
            if name == "winlogon.exe" and priority != 13:
                logger.log("WARNING", "ProcessScan", "winlogon.exe priority is not 13 %s" % process_info)
            if re.search("(Windows 7|Windows Vista)", getPlatformFull()):
                if name == "winlogon.exe" and parent_pid > 0:
                    for proc in processes:
                        if parent_pid == proc.ProcessId:
                            logger.log("WARNING", "ProcessScan",
                                       "winlogon.exe has a parent ID but should have none %s PARENTID: %s"
                                       % (process_info, str(parent_pid)))

            # Process: explorer.exe
            if path != "none":
                if name == "explorer.exe" and not t_systemroot.lower() in path.lower():
                    logger.log("WARNING", "ProcessScan", "explorer.exe path is not %%SYSTEMROOT%% %s" % process_info)
            if name == "explorer.exe" and parent_pid > 0:
                for proc in processes:
                    if parent_pid == proc.ProcessId:
                        logger.log("NOTICE", "ProcessScan",
                                   "explorer.exe has a parent ID but should have none %s" % process_info)

    def check_win_process_connections(self, process):
        pid = 0
        try:

            # Limits
            MAXIMUM_CONNECTIONS = 20

            # Counter
            connection_count = 0

            # Pid from process
            pid = process.ProcessId
            name = process.Name

            # Get psutil info about the process
            try:
                p = psutil.Process(pid)
            except Exception:
                return

            # print "Checking connections of %s" % process.Name
            for x in p.connections():

                # Evaluate a usable command line to check
                try:
                    command = process.CommandLine
                except Exception:
                    command = p.cmdline()

                if x.status == 'LISTEN':
                    connection_count += 1
                    # logger.log("NOTICE", "ProcessScan",
                    #            "Listening process PID: %s NAME: %s COMMAND: %s IP: %s PORT: %s" % (
                    #                str(pid), name, command, str(x.laddr[0]), str(x.laddr[1])))
                    if str(x.laddr[1]) == "0":
                        logger.log("WARNING", "ProcessScan",
                                   "Listening on Port 0 PID: %s NAME: %s IP: %s PORT: %s\n COMMAND: %s\n" % (
                                       str(pid), name, command, str(x.laddr[0]), str(x.laddr[1])))

                if x.status == 'ESTABLISHED' or x.status == 'SYN_SENT':

                    # Lookup Remote IP
                    # Geo IP Lookup removed

                    # Check keyword in remote address
                    is_match, description = self.check_c2(str(x.raddr[0]))
                    if is_match:
                        logger.log("ALERT", "ProcessScan",
                                   "Malware Domain/IP match in remote address PID: %s NAME: %s "
                                   "IP: %s PORT: %s\n DESC: %s\n COMMAND: %s\n" % (
                                       str(pid), name, str(x.raddr[0]), str(x.raddr[1]), description, command))

                    # Full list
                    connection_count += 1
                    exclude_ip = "127.0.0.1 ::1"
                    if str(x.laddr[0]) in exclude_ip and str(x.raddr[0]) in exclude_ip:
                        continue
                    else:
                        logger.log("NOTICE", "ProcessScan",
                                   x.status + " connection PID: %s NAME: %s LIP: %s "
                                              "LPORT: %s RIP: %s RPORT: %s\n COMMAND: %s" % (str(pid), name,
                                                                                             str(x.laddr[0]),
                                                                                             str(x.laddr[1]),
                                                                                             str(x.raddr[0]),
                                                                                             str(x.raddr[1]),
                                                                                             command))

                # Maximum connection output
                if connection_count > MAXIMUM_CONNECTIONS:
                    # logger.log("NOTICE", "ProcessScan", "Connection output threshold reached. Output truncated.")
                    return

        except Exception:
            logger.log("INFO", "ProcessScan",
                       "Process %s does not exist anymore or cannot be accessed" % str(pid))
            sys.exit(1)

    def scan_linux_processes(self):
        logger.log("INFO", "Init", "Initializing process scan")
        processes = psutil.process_iter()

        # App's processes
        app_pid = os.getpid()
        app_ppid = psutil.Process(os.getpid()).ppid()  # safer way to do this - os.ppid() fails in some envs

        # Counter
        c = 0
        total = sum(1 for _ in psutil.process_iter())
        for process in processes:
            try:
                # Counter
                c += 1

                print_progress(c, total)
                # Gather Process Information --------------------------------------
                process_id = process.pid
                name = process.name()
                cmd = process.cmdline()
                if len(cmd) == 0:
                    cmd = ["N/A"]
                if not name:
                    name = "N/A"
                # Process Info
                process_info = "PID: %s NAME: %s\n CMD: %s" % (str(process_id), name, cmd)

            except Exception:
                logger.log("ALERT", "ProcessScan",
                           "Error getting all process information. Did you run the scanner 'As Root'?")
                continue

            # Skip own process ----------------------------------------------------
            if app_pid == process_id or app_ppid == process_id:
                continue

            # Skeleton Key Malware Process
            for command in cmd:
                if re.search(r'psexec .* [a-fA-F0-9]{32}', command, re.IGNORECASE):
                    logger.log("WARNING", "ProcessScan",
                               "Process that looks like SKELETON KEY psexec execution detected %s" % process_info)

            # Yara rule match
            # only on processes with a small working set size
            if process_exists(process_id):
                try:
                    alerts = []
                    for rules in self.yara_rules:
                        # continue - fast switch
                        matches = rules.match(pid=process_id)
                        if matches:
                            for match in matches:

                                # Preset memory_rule
                                memory_rule = 1

                                # Built-in rules have meta fields (cannot be expected from custom rules)
                                if hasattr(match, 'meta'):

                                    # If a score is given
                                    if 'memory' in match.meta:
                                        memory_rule = int(match.meta['memory'])

                                # If rule is meant to be applied to process memory as well
                                if memory_rule == 1:
                                    # print match.rule
                                    alerts.append("Yara Rule MATCH: %s %s" % (match.rule, process_info))

                    if len(alerts) > 5:
                        logger.log("WARNING", "ProcessScan",
                                   "Too many matches on process memory - most likely a false positive %s"
                                   % process_info)
                    elif len(alerts) > 0:
                        for alert in alerts:
                            logger.log("ALERT", "ProcessScan", alert)
                except Exception:
                    pass
            ###############################################################
            # THOR Process Connection Checks
            self.check_linux_process_connections(process)
        print("")
        logger.log("INFO", "Init", "Process scan finish.")

    def check_linux_process_connections(self, process):
        process_id = None
        try:
            # Limits
            MAXIMUM_CONNECTIONS = 20

            # Counter
            connection_count = 0

            # Pid from process
            process_id = process.pid
            name = process.name()

            # print "Checking connections of %s" % process.Name
            for x in process.connections():

                # Evaluate a usable command line to check
                try:
                    command = process.cmdline()
                except Exception:
                    command = "N/A"

                if x.status == 'LISTEN':
                    connection_count += 1

                    if str(x.laddr[1]) == "0":
                        logger.log("WARNING", "ProcessScan",
                                   "Listening on Port 0 PID: %s NAME: %s  IP: %s PORT: %s\n COMMAND: %s\n" % (
                                       str(process_id), name, str(x.laddr[0]), str(x.laddr[1]), command))

                if x.status == 'ESTABLISHED' or x.status == 'SYN_SENT':

                    # Lookup Remote IP
                    # Geo IP Lookup removed

                    # Check keyword in remote address
                    is_match, description = self.check_c2(str(x.raddr[0]))
                    if is_match:
                        logger.log("ALERT", "ProcessScan",
                                   "Malware Domain/IP match in remote address PID: %s NAME: %s "
                                   "IP: %s PORT: %s DESC: %s\n COMMAND: %s" % (
                                       str(process_id), name, str(x.raddr[0]), str(x.raddr[1]), description, command))

                    # Full list
                    connection_count += 1
                    if str(x.raddr[0]) not in "127.0.0.1" and command is not None:
                        print("")
                        logger.log("NOTICE", "ProcessScan",
                                   "Established connection PID: %s NAME: %s LIP: %s "
                                   "LPORT: %s RIP: %s RPORT: %s\n COMMAND: %s" % (
                                       str(process_id), name, str(x.laddr[0]), str(x.laddr[1]),
                                       str(x.raddr[0]), str(x.raddr[1]), command))

                # Maximum connection output
                if connection_count > MAXIMUM_CONNECTIONS:
                    logger.log("NOTICE", "ProcessScan", "Connection output threshold reached. Output truncated.")
                    return

        except Exception:
            traceback.print_exc()
            logger.log("INFO", "ProcessScan",
                       "Process %s does not exist anymore or cannot be accessed" % str(process_id))
            sys.exit(1)

    def check_c2(self, remote_system):
        # IP - exact match
        if is_ip(remote_system):
            for c2 in self.c2_server:
                # if C2 definition is CIDR network
                if is_cidr(c2):
                    if ip_in_net(remote_system, c2):
                        return True, self.c2_server[c2]
                # if C2 is ip or else
                if c2 == remote_system:
                    return True, self.c2_server[c2]
        # Domain - remote system contains c2
        else:
            for c2 in self.c2_server:
                if c2 in remote_system:
                    return True, self.c2_server[c2]

        return False, ""

    def initialize_c2_iocs(self, ioc_directory):
        ioc_filenames = None
        try:
            for ioc_filenames in os.listdir(ioc_directory):
                try:
                    if 'c2' in ioc_filenames:
                        with codecs.open(os.path.join(ioc_directory, ioc_filenames), 'r', encoding='utf-8') as file:
                            lines = file.readlines()

                            # Last Comment Line
                            last_comment = ""

                            for line in lines:
                                try:
                                    # Comments and empty lines
                                    if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                        last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                        continue

                                    # Split the IOC line
                                    if ";" in line:
                                        line = line.rstrip(" ").rstrip("\n\r")
                                        row = line.split(';')
                                        c2 = row[0]
                                        # LOKI doesn't use the C2 score (only THOR Lite)
                                        # score = row[1]

                                        # Elements without description
                                    else:
                                        c2 = line

                                    # Check length
                                    if len(c2) < 4:
                                        logger.log("NOTICE", "Init",
                                                   "C2 server definition is suspiciously short - will not add %s" % c2)
                                        continue

                                    # Add to the LOKI iocs
                                    self.c2_server[c2.lower()] = last_comment

                                except Exception:
                                    logger.log("ERROR", "Init", "Cannot read line: %s" % line)
                                    sys.exit(1)
                except OSError:
                    logger.log("ERROR", "Init", "No such file or directory")
        except Exception:
            logger.log("ERROR", "Init", "Error reading Hash file: %s" % ioc_filenames)

    def initialize_filename_iocs(self, ioc_directory):
        return
        ioc_filename = None
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if 'filename' in ioc_filename:
                    with codecs.open(os.path.join(ioc_directory, ioc_filename), 'r', encoding='utf-8') as file:
                        lines = file.readlines()

                        # Last Comment Line
                        last_comment = ""
                        # Initialize score variable
                        score = 0
                        # Initialize empty description
                        desc = ""

                        for line in lines:
                            try:
                                # Empty
                                if re.search(r'^[\s]*$', line):
                                    continue

                                # Comments
                                if re.search(r'^#', line):
                                    last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                    continue

                                # Elements with description
                                if ";" in line:
                                    line = line.rstrip(" ").rstrip("\n\r")
                                    row = line.split(';')
                                    regex = row[0]
                                    score = row[1]
                                    if len(row) > 2:
                                        regex_fp = row[2]
                                    desc = last_comment

                                # Elements without description
                                else:
                                    regex = line

                                # Replace environment variables
                                regex = replaceEnvVars(regex)
                                # OS specific transforms
                                regex = transformOS(regex, os_platform)

                                # If false positive definition exists
                                regex_fp_comp = None
                                if 'regex_fp' in locals():
                                    # Replacements
                                    regex_fp = replaceEnvVars(regex_fp)
                                    regex_fp = transformOS(regex_fp, os_platform)
                                    # String regex as key - value is compiled regex of false positive values
                                    regex_fp_comp = re.compile(regex_fp)

                                # Create dictionary with IOC data
                                fioc = {'regex': re.compile(regex), 'score': score, 'description': desc,
                                        'regex_fp': regex_fp_comp}
                                self.filename_iocs.append(fioc)

                            except Exception:
                                logger.log("ERROR", "Init", "Error reading line: %s" % line)
        except Exception:
            if 'ioc_filename' in locals():
                logger.log("ERROR", "Init", "Error reading IOC file: %s" % ioc_filename)
            else:
                logger.log("ERROR", "Init", "Error reading files from IOC folder: %s" % ioc_directory)
            sys.exit(1)

    def initialize_yara_rules(self):
        yaraRuleFile = None
        yaraRules = ""
        dummy = ""
        rule_count = 0

        try:
            for yara_rule_directory in self.yara_rule_directories:
                if not os.path.exists(yara_rule_directory):
                    continue
                # logger.log("INFO", "Init", "Processing YARA rules folder {0}".format(yara_rule_directory))
                for root, directories, files in os.walk(yara_rule_directory, onerror=walk_error, followlinks=False):
                    for file in files:
                        try:
                            # Full Path
                            yaraRuleFile = os.path.join(root, file)

                            # Skip hidden, backup or system related files
                            if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                                continue

                            # Extension
                            extension = os.path.splitext(file)[1].lower()

                            # Skip all files that don't have *.yar or *.yara extensions
                            if extension != ".yar" and extension != ".yara":
                                continue

                            with open(yaraRuleFile, 'r') as yfile:
                                yara_rule_data = yfile.read()

                            # Test Compile
                            try:
                                rule_count += 1
                            except Exception:
                                logger.log("ERROR", "Init", "Error while initializing Yara rule %s ERROR: %s"
                                           % (file, sys.exc_info()[1]))
                                continue

                            # Add the rule
                            yaraRules += yara_rule_data

                        except Exception:
                            logger.log("ERROR", "Init",
                                       "Error reading signature file %s ERROR: %s" % (yaraRuleFile, sys.exc_info()[1]))

            # Compile
            try:
                # logger.log("INFO", "Init", "Initializing all YARA rules at once (composed string of all rule files)")
                compiledRules = yara.compile(source=yaraRules, externals={
                    'filename': dummy,
                    'filepath': dummy,
                    'extension': dummy,
                    'filetype': dummy,
                    'md5': dummy,
                    'owner': dummy,
                })
                logger.log("INFO", "Init", "Initialized %d Yara rules" % rule_count)
            except Exception:
                logger.log("ERROR", "Init",
                           "Error during YARA rule compilation ERROR: %s - please fix the issue in the rule set" %
                           sys.exc_info()[1])
                sys.exit(1)

            # Add YARA rules
            self.yara_rules.append(compiledRules)

        except Exception:
            logger.log("ERROR", "Init", "Error reading signature folder /signatures/")
            traceback.print_exc()
            sys.exit(1)

    def initialize_hash_iocs(self, ioc_directory, false_positive=False):
        ioc_filename = None
        HASH_WHITELIST = [  # Empty file
            int('d41d8cd98f00b204e9800998ecf8427e', 16),
            int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16),
            int('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 16),
            # One byte line break file (Unix) 0x0a
            int('68b329da9893e34099c7d8ad5cb9c940', 16),
            int('adc83b19e793491b1c6ea0fd8b46cd9f32e592fc', 16),
            int('01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', 16),
            # One byte line break file (Windows) 0x0d0a
            int('81051bcc2cf1bedf378224b0a93e2877', 16),
            int('ba8ab5a0280b953aa97435ff8946cbcbb2755a27', 16),
            int('7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6', 16),
        ]
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if 'hash' in ioc_filename:
                    if false_positive and 'falsepositive' not in ioc_filename:
                        continue
                    with codecs.open(os.path.join(ioc_directory, ioc_filename), 'r', encoding='utf-8') as file:
                        lines = file.readlines()

                        for line in lines:
                            try:
                                if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                    continue
                                row = line.split(';')
                                file_hash = row[0].lower()
                                comment = row[1].rstrip(" ").rstrip("\n")
                                # Empty File Hash
                                if file_hash in HASH_WHITELIST:
                                    continue
                                # Else - check which type it is
                                if len(file_hash) == 32:
                                    self.hashes_md5[int(file_hash, 16)] = comment
                                if len(file_hash) == 40:
                                    self.hashes_sha1[int(file_hash, 16)] = comment
                                if len(file_hash) == 64:
                                    self.hashes_sha256[int(file_hash, 16)] = comment
                                if false_positive:
                                    self.false_hashes[int(file_hash, 16)] = comment
                            except Exception:
                                logger.log("ERROR", "Init", "Cannot read line: %s" % line)

            # create sorted lists with just the integer values of the hashes for quick binary search
            self.hashes_md5_list = list(self.hashes_md5.keys())
            self.hashes_md5_list.sort()
            self.hashes_sha1_list = list(self.hashes_sha1.keys())
            self.hashes_sha1_list.sort()
            self.hashes_sha256_list = list(self.hashes_sha256.keys())
            self.hashes_sha256_list.sort()

        except Exception:
            logger.log("ERROR", "Init", "Error reading Hash file: %s" % ioc_filename)

    def initialize_filetype_magics(self, filetype_magics_file):
        try:
            with open(filetype_magics_file, 'r') as config:
                lines = config.readlines()

            for line in lines:
                try:
                    if re.search(r'^#', line) or re.search(r'^[\s]*$', line) or ";" not in line:
                        continue

                    (sig_raw, description) = line.rstrip("\n").split(";")
                    sig = re.sub(r' ', '', sig_raw)

                    if len(sig) > self.max_filetype_magics:
                        self.max_filetype_magics = len(sig)

                    # print "%s - %s" % ( sig, description )
                    self.filetype_magics[sig] = description

                except Exception:
                    logger.log("ERROR", "Init", "Cannot read line: %s" % line)

        except Exception:
            traceback.print_exc()
            logger.log("ERROR", "Init", "Error reading Hash file: %s" % filetype_magics_file)
            sys.exit(1)

    def initialize_excludes(self, excludes_file):
        try:
            excludes = []
            with open(excludes_file, 'r') as config:
                lines = config.read().splitlines()

            for line in lines:
                if re.search(r'^[\s]*#', line):
                    continue
                try:
                    # If the line contains something
                    if re.search(r'\w', line):
                        regex = re.compile(line, re.IGNORECASE)
                        excludes.append(regex)
                except Exception:
                    logger.log("ERROR", "Init", "Cannot compile regex: %s" % line)

            self.fullExcludes = excludes

        except Exception:
            logger.log("NOTICE", "Init", "Error reading excludes file: %s" % excludes_file)


def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        traceback.print_exc()
        sys.exit(1)


def is64bit():
    """
    Checks if the system has a 64bit processor architecture
    :return arch:
    """
    return platform.machine().endswith('64')


def process_exists(pid):
    """
    Checks if a given process is running
    :param pid:
    :return:
    """
    return psutil.pid_exists(pid)


def walk_error(err):
    if "Error 3" in str(err):
        print("Directory walk error")


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    try:
        print("------------------------------------------------------------------------------\n")
    except Exception:
        pass
    sys.exit(0)


def main():
    # Parse Arguments
    parser = argparse.ArgumentParser(description='WebShell Scanner')
    parser.add_argument('-p', '--path', help='Path to scan', required=True)
    parser.add_argument('-f', '--full_scan', help='Full scan', default=False, action='store_true')
    parser.add_argument('-sp', '--scan_process', help='Scan process', default=False, action='store_true')
    parser.add_argument('-o', '--out_file', help='Write to file', default="output.log")
    parser.add_argument('-q', '--quarantine', help='Rename and move to quarantine areas', default=False,
                        action='store_true')
    parser.add_argument('--force', action='store_true',
                        help='Force the scan on a certain folder (use with caution)', default=False)

    args = parser.parse_args()

    return args


# MAIN ################################################################
if __name__ == '__main__':

    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Argument parsing
    args = main()

    # Logger
    logger = Logger(getHostname(os_platform),
                    platform=os_platform, caller='main', VERSION=VERSION, log_file=args.out_file)

    logger.log("NOTICE", "Init", "Starting Webshell Scan SYSTEM: {0} TIME: {1} PLATFORM: {2}".format(
        getHostname(os_platform), getSyslogTimestamp(), getPlatformFull()))

    # Scanner
    scanner = Scanner()

    # Check if admin
    isRoot = False
    if os_platform == "windows":
        if shell.IsUserAnAdmin():
            isRoot = True
            logger.log("INFO", "Init", "Current user has Administrator rights - very good")
        else:
            logger.log("NOTICE", "Init", "Program should be run as 'Administrator' to ensure all access rights "
                                         "to process memory and file objects.")
    elif os_platform == "linux":
        if os.geteuid() == 0:
            isRoot = True
            logger.log("INFO", "Init", "Current user is root - very good")
        else:
            logger.log("NOTICE", "Init", "Program should be run as 'root' to ensure all "
                                         "access rights to process memory and file objects.")
    else:
        logger.log("NOTICE", "Init", "This system is not supported by this program")
        sys.exit(1)

    FULL_SCAN = args.full_scan

    # Set process to nice priority ------------------------------------
    if os_platform == "windows":
        setNice(logger)

    # Scan Processes --------------------------------------------------
    if isRoot:
        if args.scan_process and os_platform == "windows":
            scanner.scan_win_processes()
        elif args.scan_process and os_platform == "linux":
            scanner.scan_linux_processes()
    else:
        logger.log("NOTICE", "Init", "Skipping process memory check. User has no root rights.")
    # Scan Path -------------------------------------------------------
    # Set default
    defaultPath = args.path

    # Drives evaluation
    scanner.scan_path(defaultPath)

    # Result ----------------------------------------------------------
    logger.log("NOTICE", "Results",
               "Results: {0} alerts, {1} warnings, {2} notices".format(logger.alerts, logger.warnings, logger.notices))
    if logger.alerts:
        logger.log("RESULT", "Results", "Indicators detected!")
    elif logger.warnings:
        logger.log("RESULT", "Results", "Suspicious objects detected!")
    else:
        logger.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN.")

    logger.log("NOTICE", "Results",
               "Log file is stored in: {0}{1}{2}".format(get_application_path(), "/logs/".replace("/", os.sep),
                                                         args.out_file))
    logger.log("NOTICE", "Results",
               "Finished Webshell Scan SYSTEM: %s TIME: %s" % (getHostname(os_platform), getSyslogTimestamp()))

sys.exit(0)
