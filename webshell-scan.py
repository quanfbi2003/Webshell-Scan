# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import argparse
import shutil
import signal as signal_module
import stat
from bisect import bisect_left
from sys import platform as _platform
import os
import zipfile

import py7zr
import rarfile
import tarfile
import tempfile
import shutil
import gzip
import bz2
import lzma
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
VERSION = "v1.8"

# Platform
os_platform = ""

if _platform == "win32":
    os_platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

# CSV file
fileInfo_csv = {"FILE": [], "SCORE": [], "DESCRIPTION": [], "EXTENSION": [], "TIME": []}



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
    def get_file_data(file_path):
        fileData = b''
        try:
            # Read file complete
            with open(file_path, 'rb') as f:
                fileData = f.read()
        except Exception:
            logger.log("ERROR", "FileScan", "Cannot open file %s (access denied)" % file_path)
        finally:
            return fileData

    @staticmethod
    def separate_rule(text):
        count = 0
        res = []
        for line in text.strip().split("\n"):
            if line.startswith("rule ") or line.startswith("private rule ") or line.startswith("private global rule "):
                res.append("")
                count += 1
            if count > 0:
                res[count - 1] = res[count - 1] + "\n" + line

        return res

    @staticmethod
    def check_yara_rule(rule_text, new_rule):
        dummy = ""
        try:
            yara.compile(source=rule_text, externals={
                'filename': dummy,
                'file_path': dummy,
                'extension': dummy,
                'filetype': dummy,
                'md5': dummy,
                'owner': dummy,
            })
            return True
        except Exception as e:
            # print("Syntax error in rule: {0}".format(e))
            # if "undefined identifier" in str(e):
            #     print(new_rule)
            return False

    def is_supported_file(self, file_path):
        """
        Kiểm tra xem file có phải loại được hỗ trợ không dựa trên loại file từ get_file_type.
        """
        file_type = get_file_type(file_path, self.filetype_magics, self.max_filetype_magics, logger)
        supported_types = ['ZIP', 'JAR', 'Office', 'PKZIP', 'WinZIP', 'PKSFX', 'RAR', '7Zip', 'GZIP', 'BZip2']
        return file_type in supported_types

    def extract_to_temp(self, file_path):
        """
        Giải nén file vào thư mục tạm thời dựa trên loại file.
        """
        file_type = get_file_type(file_path, self.filetype_magics, self.max_filetype_magics, logger)
        # Tạo thư mục ./temp/ nếu chưa tồn tại
        base_temp_dir = "temp/".replace("/", os.sep)
        if not os.path.exists(base_temp_dir):
            os.makedirs(base_temp_dir)

        # Tạo tên thư mục tạm duy nhất bằng cách sử dụng timestamp
        temp_dir_name = f"extracted_{int(time.time() * 1000)}"
        temp_dir = os.path.join(base_temp_dir, temp_dir_name)
        os.makedirs(temp_dir)
        # print(f"Extracting to: {temp_dir}")

        try:
            if file_type in ['ZIP', 'JAR', 'Office', 'PKZIP', 'WinZIP', 'PKSFX']:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            elif file_type == 'RAR':
                try:
                    with rarfile.RarFile(file_path, 'r') as rar_ref:
                        rar_ref.extractall(temp_dir)
                except ImportError:
                    print("rarfile not installed, please install it and ensure unrar is available")
                    return None
            elif file_type == '7Zip':
                try:
                    with py7zr.SevenZipFile(file_path, 'r') as z:
                        z.extractall(temp_dir)
                except ImportError:
                    print("py7zr not installed, please install it")
                    return None
            elif file_type == 'GZIP':
                with gzip.open(file_path, 'rb') as gz_ref:
                    output_file = os.path.join(temp_dir, os.path.basename(file_path) + '.decompressed')
                    with open(output_file, 'wb') as out_file:
                        shutil.copyfileobj(gz_ref, out_file)
            elif file_type == 'BZip2':
                with bz2.open(file_path, 'rb') as bz2_ref:
                    output_file = os.path.join(temp_dir, os.path.basename(file_path) + '.decompressed')
                    with open(output_file, 'wb') as out_file:
                        shutil.copyfileobj(bz2_ref, out_file)
            else:
                print(f"Unsupported file type: {file_type}")
                return None
            return temp_dir
        except Exception as e:
            print(f"Error extracting file: {e}")
            return None

    @staticmethod
    def delete_temp_dir(temp_dir):
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            # print(f"Deleted temporary directory: {temp_dir}")
        else:
            # print(f"Directory not found: {temp_dir}")
            pass

    def scan_path(self, path):
        global MESSAGE
        MESSAGE = []
        if not os.path.exists(path):
            logger.log("ERROR", "FileScan", f"None Existing Scanning Path {path} ...")
            return

        logger.log("INFO", "FileScan", f"Scanning Path {path} ...")
        for skip in self.startExcludes:
            if path.startswith(skip):
                logger.log("INFO", "FileScan", f"Skipping {skip} directory [fixed excludes] (try using --force)")
                return

        c = 0
        total = 0

        for root, directories, files in os.walk(path, onerror=self.walk_error, followlinks=False):
            newDirectories = []
            for directory in directories:
                skipIt = False
                completePath = os.path.join(root, directory).lower() + os.sep
                for skip in self.startExcludes:
                    if completePath.startswith(skip):
                        skipIt = True
                if not skipIt:
                    newDirectories.append(directory)
            directories[:] = newDirectories

            total += len(files)

            for filename in files:
                try:
                    file_path = os.path.join(root, filename)
                    if not self.should_scan_file(file_path):
                        continue

                    c += 1
                    logger.log("DEBUG", "PROCESSING", f"{print_progress(c, total)}\t{file_path}\tSize: {os.stat(file_path).st_size / 1024 / 1024} MB\t CSV: {sys.getsizeof(fileInfo_csv)} bytes")

                    # Kiểm tra xem file có phải là file nén không
                    if self.is_supported_file(file_path):
                        self.scan_compressed_file(file_path, file_path)
                    else:
                        self.scan_single_file(file_path)
                except Exception:
                    traceback.print_exc()

        MESSAGE.sort(key=lambda x: x[0], reverse=True)
        for i in MESSAGE:
            logger.log(i[1], "FileScan", i[2])

    def should_scan_file(self, file_path):
        """Kiểm tra xem file có nên được quét hay không"""
        if self.app_path.lower() in file_path.lower():
            return False
        if os.stat(file_path).st_size > 150 * 1024 * 1024:
            logger.log("ERROR", "PROCESSING", f"{file_path}\tSize: {os.stat(file_path).st_size / 1024 / 1024} MB > 150 MB")
            return False
        for skip in self.fullExcludes:
            if skip.search(file_path):
                return False
        if os_platform == "linux" or os_platform == "macos":
            for skip in self.LINUX_PATH_SKIPS_END:
                if file_path.endswith(skip):
                    if self.LINUX_PATH_SKIPS_END[skip] == 0:
                        self.LINUX_PATH_SKIPS_END[skip] = 1
                        return False
            mode = os.stat(file_path).st_mode
            if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(mode) or stat.S_ISSOCK(mode):
                return False
        return True

    def scan_single_file(self, file_path, parent_file=None):
        """Quét một file đơn lẻ và ghi nhận kết quả"""
        reasons = []
        total_score = 0
        extension = os.path.splitext(file_path)[1].lower()
        fileType = get_file_type(file_path, self.filetype_magics, self.max_filetype_magics, logger)
        fileData = self.get_file_data(file_path)

        # File Name Checks
        for fioc in self.filename_iocs:
            match = fioc['regex'].search(file_path)
            if match and (not fioc['regex_fp'] or not fioc['regex_fp'].search(file_path)):
                reasons.append(f"File Name IOC matched PATTERN: {fioc['regex'].pattern} SUBSCORE: {fioc['score']} DESC: {fioc['description']}")
                total_score += int(fioc['score'])

        # Hash Check
        md5, sha1, sha256 = generateHashes(fileData)
        md5_num, sha1_num, sha256_num = int(md5, 16), int(sha1, 16), int(sha256, 16)
        if md5_num in self.false_hashes or sha1_num in self.false_hashes or sha256_num in self.false_hashes:
            return
        matchType, matchDesc, matchHash = None, None, None
        if self.ioc_contains(self, self.hashes_md5_list, md5_num):
            matchType, matchDesc, matchHash = "MD5", self.hashes_md5[md5_num], md5
        elif self.ioc_contains(self, self.hashes_sha1_list, sha1_num):
            matchType, matchDesc, matchHash = "SHA1", self.hashes_sha1[sha1_num], sha1
        elif self.ioc_contains(self, self.hashes_sha256_list, sha256_num):
            matchType, matchDesc, matchHash = "SHA256", self.hashes_sha256[sha256_num], sha256
        if matchType:
            reasons.append(f"Malware Hash TYPE: {matchType} HASH: {matchHash} SUBSCORE: 100 DESC: {matchDesc}")
            total_score += 100

        # Yara Check
        try:
            for score, rule, description, reference, matched_strings, author in self.scan_data(
                fileData=fileData,
                fileType=fileType,
                fileName=os.path.basename(file_path).encode('ascii', errors='replace'),
                file_path=file_path.encode('ascii', errors='replace'),
                extension=extension,
                md5=md5
            ):
                message = f"Yara Rule MATCH: {rule} SUBSCORE: {score} DESCRIPTION: {description} REF: {reference} AUTHOR: {author}"
                if matched_strings:
                    message += f" MATCHES: {matched_strings}"
                total_score += score
                reasons.append(message)
        except Exception:
            logger.log("ERROR", "FileScan", f"Cannot YARA scan file: {file_path}")

        if total_score >= 40:
            self.log_findings(file_path, total_score, reasons, extension, parent_file)

    def scan_compressed_file(self, file_path, parent_file):
        """Quét file nén và các file bên trong"""
        temp_dir = self.extract_to_temp(file_path)
        if temp_dir is not None:
            try:
                for root, _, files in os.walk(temp_dir):
                    for filename in files:
                        nested_file = os.path.join(root, filename)
                        if self.should_scan_file(nested_file):
                            if self.is_supported_file(nested_file):
                                self.scan_compressed_file(nested_file, parent_file)
                            else:
                                self.scan_single_file(nested_file, parent_file)
            finally:
                self.delete_temp_dir(temp_dir)

    def log_findings(self, file_path, total_score, reasons, extension, parent_file=None):
        """Ghi nhận kết quả quét"""
        fileInfo = f"===========================================================\nFILE: {file_path}\n SCORE: {total_score}{getAgeString(file_path)}\n"
        if parent_file:
            fileInfo = fileInfo.replace("\nFILE:", f"\nPARENT FILE: {parent_file}\nFILE:")
        message_csv = ""
        message_type = "INFO"
        if total_score >= 100:
            message_type = "ALERT"
        elif total_score >= 60:
            message_type = "WARNING"
        elif total_score >= 40:
            message_type = "NOTICE"

        message_body = fileInfo
        for i, r in enumerate(reasons):
            message_body += f"\tREASON_{i + 1}: {r}\n"
            message_csv += f"REASON_{i + 1}: {r}\n"
        if args.quarantine and "===========================================================" in message_body:
            src = file_path if not parent_file else parent_file
            filename = os.path.basename(src.replace("/", os.sep)) + "." + str(int(time.time()))
            dst = os.path.join(self.app_path, ("quarantine/" + filename).replace("/", os.sep))
            try:
                if os.path.exists(src):
                    shutil.move(src, dst)
                message_body += f"FILE MOVED TO QUARANTINE: {dst}\n"
            except Exception:
                message_body += "FILE CAN NOT MOVED TO QUARANTINE!!!\n"
        MESSAGE.append([total_score, message_type, message_body])
        fileInfo_csv["FILE"].append(file_path if not parent_file else parent_file)
        fileInfo_csv["SCORE"].append(total_score)
        fileInfo_csv["TIME"].append(getAgeString(file_path))
        fileInfo_csv["DESCRIPTION"].append(message_csv)
        fileInfo_csv["EXTENSION"].append(extension)


    def scan_data(self, fileData, fileType="-", fileName=b"-", file_path=b"-", extension=b"-", md5="-"):
        try:
            # Duyệt qua từng quy tắc YARA đã biên dịch và áp dụng chúng riêng biệt
            for rule in self.yara_rules:
                matches = rule.match(data=fileData, externals={
                    'filename': fileName.decode('utf-8'),
                    'file_path': file_path.decode('utf-8'),
                    'extension': extension,
                    'filetype': fileType,
                    'md5': md5,
                    'owner': "dummy"
                })

                # Nếu có sự khớp, trả về thông tin về quy tắc và mô tả
                if matches:
                    for match in matches:
                        score = 70  # Mặc định điểm số cho mỗi quy tắc
                        description = "not set"
                        reference = "-"
                        author = "-"
                        if hasattr(match, 'meta'):
                            if 'description' in match.meta:
                                description = match.meta['description']
                            if 'cluster' in match.meta:
                                description = f"IceWater Cluster {match.meta['cluster']}"

                            if 'reference' in match.meta:
                                reference = match.meta['reference']
                            if 'author' in match.meta:
                                author = match.meta['author']

                            if 'score' in match.meta:
                                score = int(match.meta['score'])

                        matched_strings = ""
                        if hasattr(match, 'strings'):
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
        yara_rules = []  # Danh sách lưu trữ các quy tắc YARA riêng biệt

        try:
            for yara_rule_directory in self.yara_rule_directories:
                print(yara_rule_directory)
                if not os.path.exists(yara_rule_directory):
                    continue
                # Duyệt qua các tệp trong thư mục quy tắc
                for root, directories, files in os.walk(yara_rule_directory, onerror=self.walk_error,
                                                        followlinks=False):
                    for file in files:
                        print(file)
                        try:
                            # Kiểm tra phần mở rộng của tệp (chỉ chấp nhận *.yar hoặc *.yara)
                            extension = os.path.splitext(file)[1].lower()
                            if extension != ".yar" and extension != ".yara":
                                continue

                            # Đọc nội dung tệp YARA
                            yaraRuleFile = os.path.join(root, file)
                            print(yaraRuleFile)

                            with open(yaraRuleFile, 'r') as yfile:
                                yara_rule_data = yfile.read()
                            print(len(yara_rule_data))
                            # Biên dịch từng quy tắc YARA riêng biệt
                            try:
                                compiled_rule = yara.compile(source=yara_rule_data)
                                print(compiled_rule)
                                yara_rules.append(compiled_rule)
                            except Exception:
                                res = ""
                                imports = "\n".join(re.findall(r'import\s+".+?"$', yara_rule_data, re.MULTILINE))
                                rules = re.findall(r'rule\s.*?{.*?condition:.*?}', yara_rule_data, re.DOTALL)

                                for rule in rules:
                                    separate = self.separate_rule(rule)
                                    for ru in separate:
                                        temp_combined = res + ru + "\n"
                                        if self.check_yara_rule(imports + temp_combined, ru):
                                            res = temp_combined
                                yara_rules.append(yara.compile(source=(imports + res)))

                        except Exception:
                            # traceback.print_exc()
                            logger.log("ERROR", "Init",
                                       f"Error while initializing YARA rule {file} ERROR: {sys.exc_info()[1]}")

            # Lưu trữ các quy tắc đã biên dịch vào biến đối tượng
            self.yara_rules = yara_rules
            logger.log("INFO", "Init", f"Initialized {len(yara_rules)} YARA rules")

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
                    platform=os_platform, caller='main', VERSION=VERSION)

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

    logger.log("NOTICE", "Results", f"Log file is stored in: {scanner.get_application_path()}{ '/logs/'.replace('/', os.sep)}")
    logger.log("NOTICE", "Results", f"Finished Webshell Scan SYSTEM: {getHostname(os_platform)} TIME: {getSyslogTimestamp()}")

sys.exit(0)
