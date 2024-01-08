# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import argparse
import shutil
import signal as signal_module
import stat
from bisect import bisect_left
from sys import platform as _platform

import yara  # install 'yara-python' module not the outdated 'yara' module

from libs.helpers import *
from libs.logger import *

# For Windows
try:
    import wmi
    from win32comext.shell import shell
except:
    pass

# Version
VERSION = "v1.7"

# Platform
os_platform = ""

if _platform == "win32":
    os_platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

# CSV file
fileInfo_csv = {"FILE": [], "SCORE": [], "TIME": [], "DESCRIPTION": []}


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
    fullExcludeYaraRules = []
    # Platform specific excludes (match the beginning of the full path) (not user-defined)
    startExcludes = []
    fullFileInclude = [".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".phps", ".phps", ".pht", ".phtm",
                       ".phtml", ".pgif", ".shtml", ".htaccess", ".phar", ".inc", ".hphp", ".ctp", ".module",
                       ".module", ".inc", ".hphp", ".ctp", ".asp", ".aspx", ".config",
                       ".ashx", ".asmx", ".aspq", ".axd", ".cshtm", ".cshtml", ".rem", ".soap", ".vbhtm", ".vbhtml",
                       ".asa", ".cer", ".shtml", ".pl", ".pm", ".cgi", ".lib", ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
                       ".wss", ".do", ".action", ".cfm", ".cfml", ".cfc", ".dbm", ".swf", ".yaws", ".ccc", ".vbs",
                       ".ps1", ".jar", ".war", ".aar", ".ear"]
    # File type magics
    filetype_magics = {}
    max_filetype_magics = 0

    # Predefined paths to skip (Linux platform)
    LINUX_PATH_SKIPS_START = {"/proc", "/dev", "/sys/kernel/debug", "/sys/kernel/slab", "/sys/devices",
                              "/usr/src/linux"}
    MOUNTED_DEVICES = {"/media", "/volumes"}
    LINUX_PATH_SKIPS_END = {"/initctl"}

    def __init__(self):
        # Get application path
        self.app_path = self.get_application_path()

        # Check if signature database is present
        sig_dir = os.path.join(self.app_path, "libs/signature-base".replace("/", os.sep))
        if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
            logger.log("NOTICE", "Init", "The 'signature-base' subdirectory doesn't exist or is empty. "
                                         "Trying to retrieve the signature database automatically.")
            sys.exit(1)

        # Excludes
        self.initialize_excludes(os.path.join(self.app_path, "config/excludes.cfg".replace("/", os.sep)))

        self.initialize_exclude_yara_rules(
            os.path.join(self.app_path, "config/exclude_yara_rules.cfg".replace("/", os.sep)))

        # Linux static excludes
        if os_platform == "linux":
            self.startExcludes = self.LINUX_PATH_SKIPS_START | self.MOUNTED_DEVICES

        # Set IOC path
        self.ioc_path = os.path.join(self.app_path, "libs/signature-base/iocs/".replace("/", os.sep))

        # Yara rule directories
        self.yara_rule_directories.append(os.path.join(self.app_path, "libs/signature-base/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "libs/signature-base/iocs/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "libs/signature-base/3rdparty".replace("/", os.sep)))

        # Read IOCs -------------------------------------------------------
        # File Name IOCs (all files in iocs that contain 'filename')
        self.initialize_filename_iocs(self.ioc_path)
        logger.log("INFO", "Init",
                   "File Name Characteristics initialized with %s regex patterns" % len(self.filename_iocs))

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

    @staticmethod
    def get_string_matches(strings):
        try:
            string_matches = []
            matching_strings = ""
            for estring in strings:
                # print string
                extract = estring
                if not extract in string_matches:
                    string_matches.append(extract)

            string_num = 1
            for estring in string_matches:
                matching_strings += " Str" + str(string_num) + ": " + str(estring)
                string_num += 1

            # Limit string
            if len(matching_strings) > 140:
                matching_strings = matching_strings[:140] + " ... (truncated)"

            return matching_strings.lstrip(" ")
        except Exception:
            traceback.print_exc()

    @staticmethod
    def ioc_contains(self, sorted_list, value):
        # returns true if sorted_list contains value
        index = bisect_left(sorted_list, value)
        return index != len(sorted_list) and sorted_list[index] == value

    @staticmethod
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

        for root, directories, files in os.walk(path, onerror=self.walk_error, followlinks=False):
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

                    skipIt = False

                    # File size check
                    if os.stat(filePath).st_size > 20 * (1024 * 1024):
                        skipIt = True

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
                    print(filePath + "\t Size: {0} MB\t CSV: {1} bytes".format(os.stat(filePath).st_size / 1024 / 1024,
                                                                               sys.getsizeof(fileInfo_csv)))
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

                    # Evaluate Type
                    fileType = get_file_type(filePath, self.filetype_magics, self.max_filetype_magics, logger)

                    # Hash Check -------------------------------------------------------
                    # Do the check

                    # Set fileData to an empty value
                    fileData = ""

                    fileData = self.get_file_data(filePath)

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
                    if self.ioc_contains(self, self.hashes_md5_list, md5_num):
                        matchType = "MD5"
                        matchDesc = self.hashes_md5[md5_num]
                        matchHash = md5
                    if self.ioc_contains(self, self.hashes_sha1_list, sha1_num):
                        matchType = "SHA1"
                        matchDesc = self.hashes_sha1[sha1_num]
                        matchHash = sha1
                    if self.ioc_contains(self, self.hashes_sha256_list, sha256_num):
                        matchType = "SHA256"
                        matchDesc = self.hashes_sha256[sha256_num]
                        matchHash = sha256

                    # Hash string
                    if matchType:
                        reasons.append("Malware Hash TYPE: %s HASH: %s SUBSCORE: 100 DESC: %s" % (
                            matchType, matchHash, matchDesc))
                        total_score += 100

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

                    if extension not in self.fullFileInclude:
                        if total_score >= 100:
                            total_score = 99
                        elif total_score >= 60:
                            total_score = 59
                        elif total_score >= 40:
                            total_score = 40

                    # Info Line -----------------------------------------------------------------------
                    fileInfo = "===========================================================\n" \
                               "FILE: %s\n SCORE: %s%s\n " % (
                                   filePath, total_score, getAgeString(filePath))
                    message_csv = ""
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
                        message_csv += "REASON_{0}: {1}\n ".format(i + 1, r)
                    if args.quarantine and "===========================================================" in message_body:
                        src = filePath
                        filename = os.path.basename(filePath.replace("/", os.sep)) + "." + str(int(time.time()))
                        dst = os.path.join(self.app_path, ("quarantine/" + filename).replace("/", os.sep))
                        try:
                            shutil.move(src, dst)
                            message_body += "FILE MOVED TO QUARANTINE: %s\n " % dst
                        except Exception:
                            message_body += "FILE CAN NOT MOVED TO QUARANTINE!!!\n "
                    MESSAGE.append([total_score, message_type, message_body])
                    fileInfo_csv["FILE"].append(filePath)
                    fileInfo_csv["SCORE"].append(total_score)
                    fileInfo_csv["TIME"].append(getAgeString(filePath))
                    fileInfo_csv["DESCRIPTION"].append(message_csv)
                except Exception:
                    traceback.print_exc()
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
                        if match.rule in self.fullExcludeYaraRules:
                            continue
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
                            matched_strings = self.get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except Exception:
            pass

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
                                if re.search(r'^\s*$', line):
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
                for root, directories, files in os.walk(yara_rule_directory, onerror=self.walk_error,
                                                        followlinks=False):
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

                            if ("webshell" in str(yara_rule_data).lower() or "jsp" in str(yara_rule_data).lower()
                                    or "asp" in str(yara_rule_data).lower() or "php" in str(yara_rule_data).lower()
                                    or "web" in str(yara_rule_data).lower() or "shell" in str(yara_rule_data).lower()
                                    or "cmd" in str(yara_rule_data).lower()):
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
                                if re.search(r'^#', line) or re.search(r'^\s*$', line):
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
                    if re.search(r'^#', line) or re.search(r'^\s*$', line) or ";" not in line:
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
                if re.search(r'^\s*#', line):
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

    def initialize_exclude_yara_rules(self, exclude_yara_rule_file):
        try:
            excludes = []
            with open(exclude_yara_rule_file, 'r') as config:
                lines = config.read().splitlines()

            for line in lines:
                excludes.append(line)
            self.fullExcludeYaraRules = excludes

        except Exception:
            logger.log("NOTICE", "Init", "Error reading excludes file: %s" % exclude_yara_rule_file)

    @staticmethod
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

    @staticmethod
    def is64bit():
        """
        Checks if the system has a 64bit processor architecture
        :return arch:
        """
        return platform.machine().endswith('64')

    @staticmethod
    def process_exists(pid):
        """
        Checks if a given process is running
        :param pid:
        :return:
        """
        return psutil.pid_exists(pid)

    @staticmethod
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
    parser.add_argument('-o', '--out_file', help='Write to file', default="output.log")
    parser.add_argument('-q', '--quarantine', help='Rename and move to quarantine areas', default=False,
                        action='store_true')
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

    # Set process to nice priority ------------------------------------
    if os_platform == "windows":
        setNice(logger)

    # Scan Path -------------------------------------------------------
    # Set default
    defaultPath = args.path

    # Drives evaluation
    scanner.scan_path(defaultPath)

    # Result ----------------------------------------------------------
    logger.log_to_csv_file(fileInfo_csv)

    logger.log("NOTICE", "Results",
               "Results: {0} alerts, {1} warnings, {2} notices".format(logger.alerts, logger.warnings, logger.notices))
    if logger.alerts:
        logger.log("RESULT", "Results", "Indicators detected!")
    elif logger.warnings:
        logger.log("RESULT", "Results", "Suspicious objects detected!")
    else:
        logger.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN.")

    logger.log("NOTICE", "Results",
               "Log file is stored in: {0}{1}{2}".format(scanner.get_application_path(), "/logs/".replace("/", os.sep),
                                                         args.out_file))
    logger.log("NOTICE", "Results",
               "Finished Webshell Scan SYSTEM: %s TIME: %s" % (getHostname(os_platform), getSyslogTimestamp()))

sys.exit(0)
