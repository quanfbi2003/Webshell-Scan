# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import argparse
import codecs
import re
import shutil
import signal as signal_module
import stat
import time
import threading
import queue
from bisect import bisect_left
import zipfile
import tarfile
import gzip
import bz2
import lzma
import tempfile
import subprocess

from sys import platform as _platform
import yara  # install 'yara-python' module not the outdated 'yara' module
try:
    import pyssdeep
    # Create compatibility wrapper for pyssdeep
    class ssdeep_wrapper:
        @staticmethod
        def hash(data):
            """Wrapper for pyssdeep.get_hash_buffer()"""
            if isinstance(data, str):
                data = data.encode('utf-8')
            return pyssdeep.get_hash_buffer(data, len(data))
        
        @staticmethod
        def compare(hash1, hash2):
            """Wrapper for pyssdeep.compare()"""
            return pyssdeep.compare(hash1, hash2)
    
    ssdeep = ssdeep_wrapper()
except ImportError:
    ssdeep = None
    # Log warning will be in __init__

# Import helpers first (all functions)
from libs.helpers import *

# Import logger after helpers
from libs.logger import *

# For Windows
try:
    from win32comext.shell import shell
except:
    pass

# Version
VERSION = "v2.0"

# Platform
os_platform = ""

if _platform == "win32":
    os_platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

# CSV file
fileInfo_csv = {"FILE": [], "SCORE": [], "TIME": [], "DESCRIPTION": [], "EXTENSION": []}


class Scanner(object):
    # Signatures
    yara_rules = []
    filename_iocs = []
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    false_hashes = {}
    ssdeep_signatures = []  # List of (ssdeep_hash, filename) tuples
    
    # Sorted hash lists for binary search (initialized in initialize_hash_iocs)
    hashes_md5_list = []
    hashes_sha1_list = []
    hashes_sha256_list = []
    
    # Archive extraction settings
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
                         '.war', '.jar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
                         '.tar.xz', '.txz', '.ear', '.sar', '.nar'}
    MAX_ARCHIVE_SIZE = 20 * 1024 * 1024  # 20MB

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

    def __init__(self):
        # Get application path
        self.app_path = self.get_application_path()

        # Kiểm tra các thư mục bắt buộc (config, libs)
        config_dir = os.path.join(self.app_path, "config".replace("/", os.sep))
        libs_dir = os.path.join(self.app_path, "libs".replace("/", os.sep))
        
        missing_dirs = []
        if not os.path.exists(config_dir):
            missing_dirs.append(f"config ({config_dir})")
        if not os.path.exists(libs_dir):
            missing_dirs.append(f"libs ({libs_dir})")
        
        if missing_dirs:
            error_msg = f"Required directory(ies) do not exist: {', '.join(missing_dirs)}"
            logger.log("ERROR", "Init", error_msg)
            logger.log("ERROR", "Init", "Please ensure all required directories (config, libs) exist before running the scanner.")
            logger.log("ERROR", "Init", "Configuration initialization failed. Exiting.")
            sys.exit(1)

        # Tạo các thư mục cần thiết nếu chưa tồn tại (logs, quarantine)
        logs_dir = os.path.join(self.app_path, "logs".replace("/", os.sep))
        quarantine_dir = os.path.join(self.app_path, "quarantine".replace("/", os.sep))
        
        try:
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir, exist_ok=True)
                logger.log("INFO", "Init", f"Created logs directory: {logs_dir}")
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir, exist_ok=True)
                logger.log("INFO", "Init", f"Created quarantine directory: {quarantine_dir}")
        except Exception as e:
            logger.log("ERROR", "Init", f"Cannot create required directories: {str(e)}")
            sys.exit(1)

        # Check if signature database is present
        sig_dir = os.path.join(self.app_path, "libs/signature-base".replace("/", os.sep))
        if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
            logger.log("NOTICE", "Init", "The 'signature-base' subdirectory doesn't exist or is empty. "
                                         "Trying to retrieve the signature database automatically.")
            sys.exit(1)

        # Excludes
        self.initialize_excludes(os.path.join(self.app_path, "config/excludes.cfg".replace("/", os.sep)))

        # Linux static excludes
        if os_platform == "linux":
            self.startExcludes = self.LINUX_PATH_SKIPS_START | self.MOUNTED_DEVICES

        # Set IOC path
        self.ioc_path = os.path.join(self.app_path, "libs/signature-base/iocs/".replace("/", os.sep))
        
        # Set Custom path
        self.custom_path = os.path.join(self.app_path, "libs/signature-base/custom/".replace("/", os.sep))

        # Yara rule directories
        self.yara_rule_directories.append(os.path.join(self.app_path, "libs/signature-base/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "libs/signature-base/iocs/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "libs/signature-base/3rdparty".replace("/", os.sep)))
        # Add custom directory for YARA rules
        if os.path.exists(os.path.join(self.app_path, "libs/signature-base/custom/".replace("/", os.sep))):
            self.yara_rule_directories.append(
                os.path.join(self.app_path, "libs/signature-base/custom/".replace("/", os.sep)))

        # Read IOCs -------------------------------------------------------
        # File Name IOCs (all files in iocs that contain 'filename')
        # NOTE: initialize_filename_iocs is currently disabled, using initialize_filename_iocs_from_file instead
        # self.initialize_filename_iocs(self.ioc_path)
        # Read custom IOC file if exists
        custom_ioc_file = os.path.join(self.custom_path, "iocs_custom.txt")
        if os.path.exists(custom_ioc_file):
            self.initialize_filename_iocs_from_file(custom_ioc_file)
        logger.log("INFO", "Init",
                   "File Name Characteristics initialized with %s regex patterns" % len(self.filename_iocs))

        ## Hash based IOCs (all files in iocs that contain 'hash')
        self.initialize_hash_iocs(self.ioc_path)
        # Read custom IOC file if exists
        if os.path.exists(custom_ioc_file):
            self.initialize_hash_iocs_from_file(custom_ioc_file)
        logger.log("INFO", "Init", "Malicious MD5 Hashes initialized with %s hashes" % len(self.hashes_md5.keys()))
        logger.log("INFO", "Init", "Malicious SHA1 Hashes initialized with %s hashes" % len(self.hashes_sha1.keys()))
        logger.log("INFO", "Init", "Malicious SHA256 Hashes initialized with %s hashes"
                   % len(self.hashes_sha256.keys()))

        # Hash based False Positives (all files in iocs that contain 'hash' and 'falsepositive')
        self.initialize_hash_iocs(self.ioc_path, false_positive=True)
        # NOTE: custom-hash-iocs.txt chỉ chứa hash mã độc, KHÔNG phải false positive
        # Không load custom-hash-iocs.txt vào false_hashes để tránh bỏ qua file mã độc
        # Nếu cần thêm false positive, tạo file riêng hoặc thêm vào falsepositive-hashes.txt
        logger.log("INFO", "Init", "False Positive Hashes initialized with %s hashes" % len(self.false_hashes.keys()))

        # Compile Yara Rules
        self.initialize_yara_rules()

        # Initialize File Type Magic signatures
        filetype_magics_file = os.path.join(self.app_path, 'libs/signature-base/misc/file-type-signatures.txt'
                                                     .replace("/", os.sep))
        self.initialize_filetype_magics(filetype_magics_file)
        # Read custom misc file if exists
        custom_misc_file = os.path.join(self.custom_path, "misc_custom.txt")
        if os.path.exists(custom_misc_file):
            self.initialize_filetype_magics_from_file(custom_misc_file)

        # Initialize SSDeep signatures
        ssdeep_file = os.path.join(self.custom_path, "known_webshells.ssdeep")
        if os.path.exists(ssdeep_file):
            self.initialize_ssdeep_signatures(ssdeep_file)
            logger.log("INFO", "Init", "SSDeep signatures initialized with %s hashes" % len(self.ssdeep_signatures))
        else:
            logger.log("NOTICE", "Init", "SSDeep signature file not found: %s" % ssdeep_file)

    @staticmethod
    def get_string_matches(strings):
        try:
            string_matches = []
            matching_strings = ""
            for estring in strings:
                # print string
                extract = estring
                if extract not in string_matches:
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
    def ioc_contains(sorted_list, value):
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
        except Exception as e:
            logger.log("DEBUG", "FileScan", f"Cannot open file {filePath}: {str(e)}")
        finally:
            return fileData
    
    def is_archive_file(self, filePath):
        """Check if file is an archive based on extension"""
        filePath_lower = filePath.lower()
        # Check for compound extensions first (e.g., .tar.gz)
        for ext in sorted(self.ARCHIVE_EXTENSIONS, key=len, reverse=True):
            if filePath_lower.endswith(ext):
                return True, ext
        return False, None
    
    def extract_archive(self, archive_path, temp_dir):
        """Extract archive to temporary directory. Returns list of extracted file paths."""
        extracted_files = []
        try:
            is_archive, ext = self.is_archive_file(archive_path)
            if not is_archive:
                return extracted_files
            
            logger.log("DEBUG", "Archive", f"Extracting archive: {archive_path} (type: {ext})")
            
            # Create subdirectory for this archive
            archive_temp_dir = os.path.join(temp_dir, os.path.basename(archive_path) + "_extracted")
            os.makedirs(archive_temp_dir, exist_ok=True)
            
            # Extract based on archive type
            if ext in ['.zip', '.jar', '.war', '.ear', '.sar', '.nar']:
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(archive_temp_dir)
                        # Get list of extracted files
                        for member in zip_ref.namelist():
                            extracted_path = os.path.join(archive_temp_dir, member)
                            if os.path.isfile(extracted_path):
                                extracted_files.append(extracted_path)
                except zipfile.BadZipFile:
                    logger.log("WARNING", "Archive", f"Invalid ZIP file: {archive_path}")
                    return extracted_files
                    
            elif ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz']:
                try:
                    mode = 'r'
                    if ext.endswith('.gz') or ext == '.tgz':
                        mode = 'r:gz'
                    elif ext.endswith('.bz2') or ext == '.tbz2':
                        mode = 'r:bz2'
                    elif ext.endswith('.xz') or ext == '.txz':
                        mode = 'r:xz'
                    
                    with tarfile.open(archive_path, mode) as tar_ref:
                        tar_ref.extractall(archive_temp_dir)
                        # Get list of extracted files
                        for member in tar_ref.getmembers():
                            if member.isfile():
                                extracted_path = os.path.join(archive_temp_dir, member.name)
                                if os.path.isfile(extracted_path):
                                    extracted_files.append(extracted_path)
                except tarfile.TarError as e:
                    logger.log("WARNING", "Archive", f"Error extracting TAR file {archive_path}: {str(e)}")
                    return extracted_files
                    
            elif ext == '.gz':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-3])
                    with gzip.open(archive_path, 'rb') as gz_ref:
                        with open(output_path, 'wb') as out_file:
                            shutil.copyfileobj(gz_ref, out_file)
                    extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting GZ file {archive_path}: {str(e)}")
                    return extracted_files
                    
            elif ext == '.bz2':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-4])
                    with bz2.open(archive_path, 'rb') as bz2_ref:
                        with open(output_path, 'wb') as out_file:
                            shutil.copyfileobj(bz2_ref, out_file)
                    extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting BZ2 file {archive_path}: {str(e)}")
                    return extracted_files
                    
            elif ext == '.xz':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-3])
                    with lzma.open(archive_path, 'rb') as xz_ref:
                        with open(output_path, 'wb') as out_file:
                            shutil.copyfileobj(xz_ref, out_file)
                    extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting XZ file {archive_path}: {str(e)}")
                    return extracted_files
                    
            elif ext in ['.rar', '.7z']:
                # Try using 7z command line tool (if available)
                try:
                    # Check if 7z is available
                    result = subprocess.run(['7z', '--help'], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        # Extract using 7z
                        cmd = ['7z', 'x', archive_path, f'-o{archive_temp_dir}', '-y']
                        result = subprocess.run(cmd, capture_output=True, timeout=60)
                        if result.returncode == 0:
                            # Get list of extracted files
                            for root, dirs, files in os.walk(archive_temp_dir):
                                for file in files:
                                    extracted_files.append(os.path.join(root, file))
                        else:
                            logger.log("WARNING", "Archive", f"7z extraction failed for {archive_path}")
                    else:
                        logger.log("WARNING", "Archive", f"7z tool not available, cannot extract {ext} file: {archive_path}")
                except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                    logger.log("WARNING", "Archive", f"Cannot extract {ext} file {archive_path}: {str(e)}")
            
            logger.log("DEBUG", "Archive", f"Extracted {len(extracted_files)} files from {archive_path}")
            return extracted_files
            
        except Exception as e:
            logger.log("ERROR", "Archive", f"Error extracting archive {archive_path}: {str(e)}")
            return extracted_files
    
    def scan_archive_recursive(self, archive_path, temp_dir, parent_archive="", args=None):
        """Scan archive and recursively scan nested archives. Returns list of findings."""
        findings = []  # List of (file_path, score, reasons, archive_path)
        
        try:
            # Extract archive
            extracted_files = self.extract_archive(archive_path, temp_dir)
            
            if not extracted_files:
                return findings
            
            # Scan each extracted file
            for extracted_file in extracted_files:
                try:
                    # Check if extracted file is also an archive
                    is_nested_archive, nested_ext = self.is_archive_file(extracted_file)
                    
                    if is_nested_archive:
                        # Check size of nested archive
                        try:
                            nested_size = os.path.getsize(extracted_file)
                            if nested_size <= self.MAX_ARCHIVE_SIZE:
                                # Recursively scan nested archive
                                nested_parent = f"{parent_archive} -> {os.path.basename(archive_path)}" if parent_archive else os.path.basename(archive_path)
                                nested_findings = self.scan_archive_recursive(extracted_file, temp_dir, nested_parent, args)
                                findings.extend(nested_findings)
                            else:
                                logger.log("DEBUG", "Archive", f"Skipping nested archive {extracted_file} (size {nested_size} > {self.MAX_ARCHIVE_SIZE})")
                        except Exception as e:
                            logger.log("WARNING", "Archive", f"Cannot get size of nested archive {extracted_file}: {str(e)}")
                    
                    # Scan the file (whether it's an archive or not)
                    file_reasons = []
                    file_score = 0
                    
                    # Read file data
                    file_data = self.get_file_data(extracted_file)
                    if not file_data:
                        continue
                    
                    # Hash check
                    md5, sha1, sha256 = generateHashes(file_data)
                    md5_num = int(md5, 16)
                    sha1_num = int(sha1, 16)
                    sha256_num = int(sha256, 16)
                    
                    # Skip empty file
                    EMPTY_FILE_SHA1 = int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16)
                    if sha1_num == EMPTY_FILE_SHA1:
                        continue
                    
                    # False positive check
                    if md5_num in self.false_hashes or sha1_num in self.false_hashes or sha256_num in self.false_hashes:
                        continue
                    
                    # Malware hash check
                    if self.ioc_contains(self.hashes_md5_list, md5_num):
                        file_reasons.append(f"Malware Hash TYPE: MD5 HASH: {md5} SUBSCORE: 100 DESC: {self.hashes_md5[md5_num]}")
                        file_score += 100
                    if self.ioc_contains(self.hashes_sha1_list, sha1_num):
                        file_reasons.append(f"Malware Hash TYPE: SHA1 HASH: {sha1} SUBSCORE: 100 DESC: {self.hashes_sha1[sha1_num]}")
                        file_score += 100
                    if self.ioc_contains(self.hashes_sha256_list, sha256_num):
                        file_reasons.append(f"Malware Hash TYPE: SHA256 HASH: {sha256} SUBSCORE: 100 DESC: {self.hashes_sha256[sha256_num]}")
                        file_score += 100
                    
                    # SSDeep check
                    if ssdeep is not None and self.ssdeep_signatures and file_data:
                        try:
                            file_ssdeep_hash = ssdeep.hash(file_data)
                            if file_ssdeep_hash:
                                best_match_score = 0
                                best_match_hash = None
                                best_match_filename = None
                                
                                for known_hash, known_filename in self.ssdeep_signatures:
                                    try:
                                        similarity = ssdeep.compare(file_ssdeep_hash, known_hash)
                                        if similarity > best_match_score:
                                            best_match_score = similarity
                                            best_match_hash = known_hash
                                            best_match_filename = known_filename
                                    except Exception:
                                        continue
                                
                                if best_match_score >= 50:
                                    file_reasons.append(f"SSDeep Match SCORE: {best_match_score}% HASH: {best_match_hash} SUBSCORE: {best_match_score} DESC: Similar to known webshell: {best_match_filename}")
                                    file_score += best_match_score
                        except Exception:
                            pass
                    
                    # YARA check
                    try:
                        extension = os.path.splitext(extracted_file)[1].lower()
                        fileType = get_file_type(extracted_file, self.filetype_magics, self.max_filetype_magics, logger)
                        filename_str = os.path.basename(extracted_file)
                        filepath_str = extracted_file
                        
                        externals = {
                            'filename': filename_str,
                            'filepath': filepath_str,
                            'extension': extension,
                            'filetype': fileType,
                            'md5': md5,
                            'owner': "dummy"
                        }
                        
                        for rules in self.yara_rules:
                            matches = rules.match(data=file_data, externals=externals)
                            if matches:
                                for match in matches:
                                    score = 70
                                    description = "not set"
                                    reference = "-"
                                    author = "-"
                                    
                                    if hasattr(match, 'meta'):
                                        meta = match.meta
                                        if 'description' in meta:
                                            description = meta['description']
                                        if 'cluster' in meta:
                                            description = meta['cluster']
                                        if 'score' in meta:
                                            score = int(meta['score'])
                                        if 'reference' in meta:
                                            reference = meta['reference']
                                        if 'author' in meta:
                                            author = meta['author']
                                    
                                    message = f"Yara Rule MATCH: {match.rule} SUBSCORE: {score} DESCRIPTION: {description} REF: {reference} AUTHOR: {author}"
                                    file_reasons.append(message)
                                    file_score += score
                    except Exception:
                        pass
                    
                    # If file has findings, add to results
                    if file_score > 0:
                        archive_info = f" (in archive: {parent_archive} -> {os.path.basename(archive_path)})" if parent_archive else f" (in archive: {os.path.basename(archive_path)})"
                        findings.append((extracted_file + archive_info, file_score, file_reasons, archive_path))
                        
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error scanning extracted file {extracted_file}: {str(e)}")
                    continue
            
            return findings
            
        except Exception as e:
            logger.log("ERROR", "Archive", f"Error in scan_archive_recursive for {archive_path}: {str(e)}")
            return findings

    def scan_path(self, path, args=None):
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

        # Cache app_path.lower() để tránh gọi lại nhiều lần
        app_path_lower = self.app_path.lower()

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
                    yara_timeout_occurred = False  # Flag để đánh dấu YARA timeout

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

                    # Cache file stat để tránh gọi lại nhiều lần (dùng cho size check và Linux file mode)
                    try:
                        file_stat = os.stat(filePath)
                        file_size = file_stat.st_size
                    except (OSError, IOError) as e:
                        logger.log("DEBUG", "FileScan", f"Cannot stat file {filePath}: {str(e)}")
                        continue
                    
                    # Check if file is an archive and should be extracted
                    is_archive, archive_ext = self.is_archive_file(filePath)
                    if is_archive and file_size <= self.MAX_ARCHIVE_SIZE:
                        # Create temporary directory for archive extraction
                        temp_dir = tempfile.mkdtemp(prefix='webshell_scan_archive_')
                        try:
                            logger.log("INFO", "Archive", f"Scanning archive: {filePath} (size: {file_size} bytes)")
                            # Scan archive recursively
                            archive_findings = self.scan_archive_recursive(filePath, temp_dir, "", args)
                            
                            # Process findings from archive
                            if archive_findings:
                                for finding_file, finding_score, finding_reasons, original_archive in archive_findings:
                                    # Create file info for the finding - include archive path
                                    archive_path_info = f"\n ARCHIVE: {filePath}\n"
                                    fileInfo = "===========================================================\n" \
                                               "FILE: %s%s SCORE: %s%s\n " % (
                                                   finding_file, archive_path_info, finding_score, getAgeString(filePath))
                                    
                                    message_type = "INFO"
                                    if finding_score >= 100:
                                        message_type = "ALERT"
                                    elif finding_score >= 60:
                                        message_type = "WARNING"
                                    elif finding_score >= 40:
                                        message_type = "NOTICE"
                                    
                                    # Build reasons - add archive info to first reason
                                    reason_lines = []
                                    reason_csv_lines = []
                                    for i, r in enumerate(finding_reasons):
                                        reason_lines.append("\tREASON_{0}: {1}\n ".format(i + 1, r))
                                        reason_csv_lines.append("REASON_{0}: {1}\n ".format(i + 1, r))
                                    
                                    message_body = fileInfo + "".join(reason_lines)
                                    message_csv = "".join(reason_csv_lines)
                                    
                                    # Add to MESSAGE and CSV
                                    MESSAGE.append([finding_score, message_type, message_body])
                                    fileInfo_csv["FILE"].append(f"{finding_file} [ARCHIVE: {filePath}]")
                                    fileInfo_csv["SCORE"].append(finding_score)
                                    fileInfo_csv["TIME"].append(getAgeString(filePath))
                                    fileInfo_csv["DESCRIPTION"].append(message_csv)
                                    fileInfo_csv["EXTENSION"].append(extension)
                                    
                                    logger.log("INFO", "Archive", f"Found webshell in archive: {finding_file} (score: {finding_score}) in archive: {filePath}")
                            
                        except Exception as e:
                            logger.log("ERROR", "Archive", f"Error processing archive {filePath}: {str(e)}")
                        finally:
                            # Cleanup temporary directory
                            try:
                                shutil.rmtree(temp_dir, ignore_errors=True)
                                logger.log("DEBUG", "Archive", f"Cleaned up temporary directory: {temp_dir}")
                            except Exception as e:
                                logger.log("WARNING", "Archive", f"Cannot cleanup temporary directory {temp_dir}: {str(e)}")
                        
                        # Continue to next file (archive already processed)
                        continue

                    # File size check (sử dụng file_stat đã cache)
                    # if file_size > 100*(1024*1024):
                    #     skipIt = True

                    # User defined excludes
                    for skip in self.fullExcludes:
                        if skip.search(filePath):
                            skipIt = True

                    # Linux directory skip
                    if os_platform == "linux":

                        # Skip paths that end with ..
                        for skip in self.LINUX_PATH_SKIPS_END:
                            if filePath.endswith(skip):
                                skipIt = True
                                break

                        # File mode (sử dụng file_stat đã cache)
                        mode = file_stat.st_mode
                        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(
                                mode) or stat.S_ISSOCK(mode):
                            continue

                    # Skip
                    if skipIt:
                        continue

                    # Counter
                    c += 1

                    print_progress(c, total, logger)
                    print(filePath + "\t Size: {0} MB".format(file_size / 1024 / 1024))
                    # Skip program directory
                    # print appPath.lower() +" - "+ filePath.lower()
                    if app_path_lower in filePath.lower():
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

                    # Skip empty file (hashes of empty file)
                    EMPTY_FILE_MD5 = int('d41d8cd98f00b204e9800998ecf8427e', 16)
                    EMPTY_FILE_SHA1 = int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16)
                    EMPTY_FILE_SHA256 = int('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 16)
                    if md5_num == EMPTY_FILE_MD5 or sha1_num == EMPTY_FILE_SHA1 or sha256_num == EMPTY_FILE_SHA256:
                        logger.log("DEBUG", "FileScan", f"Skipping empty file: {filePath}")
                        continue

                    # False Positive Hash check
                    if md5_num in self.false_hashes or sha1_num in self.false_hashes or sha256_num in self.false_hashes:
                        continue

                    # Malware Hash
                    if self.ioc_contains(self.hashes_md5_list, md5_num):
                        matchType = "MD5"
                        matchDesc = self.hashes_md5[md5_num]
                        matchHash = md5
                    if self.ioc_contains(self.hashes_sha1_list, sha1_num):
                        matchType = "SHA1"
                        matchDesc = self.hashes_sha1[sha1_num]
                        matchHash = sha1
                    if self.ioc_contains(self.hashes_sha256_list, sha256_num):
                        matchType = "SHA256"
                        matchDesc = self.hashes_sha256[sha256_num]
                        matchHash = sha256

                    # Hash string
                    if matchType:
                        reasons.append("Malware Hash TYPE: %s HASH: %s SUBSCORE: 100 DESC: %s" % (
                            matchType, matchHash, matchDesc))
                        total_score += 100

                    # SSDeep Check -------------------------------------------------------
                    if ssdeep is not None and self.ssdeep_signatures and fileData:
                        try:
                            # Log to file only (DEBUG), not to stdout
                            logger.log("DEBUG", "SSDeep", f"Checking file with SSDeep: {filePath}")
                            # Generate SSDeep hash for the current file
                            file_ssdeep_hash = ssdeep.hash(fileData)
                            logger.log("DEBUG", "SSDeep", f"Generated SSDeep hash: {file_ssdeep_hash[:50]}... (truncated)")
                            
                            if file_ssdeep_hash:
                                # Compare with known webshells
                                best_match_score = 0
                                best_match_hash = None
                                best_match_filename = None
                                comparisons_count = 0
                                
                                for known_hash, known_filename in self.ssdeep_signatures:
                                    try:
                                        # Compare hashes (returns similarity score 0-100)
                                        similarity = ssdeep.compare(file_ssdeep_hash, known_hash)
                                        comparisons_count += 1
                                        if similarity > best_match_score:
                                            best_match_score = similarity
                                            best_match_hash = known_hash
                                            best_match_filename = known_filename
                                    except Exception as e:
                                        # Skip invalid hash comparisons
                                        logger.log("DEBUG", "SSDeep", f"Error comparing hash: {str(e)}")
                                        continue
                                
                                logger.log("DEBUG", "SSDeep", f"Compared with {comparisons_count} known signatures, best match: {best_match_score}%")
                                
                                # If similarity >= 50, consider it a match (ssdeep threshold)
                                if best_match_score >= 50:
                                    logger.log("INFO", "SSDeep", f"SSDeep match found: {best_match_score}% similarity with {best_match_filename}")
                                    reason_text = "SSDeep Match SCORE: %d%% HASH: %s SUBSCORE: 85 DESC: Similar to known webshell: %s" % (
                                        best_match_score, best_match_hash, best_match_filename)
                                    reasons.append(reason_text)
                                    total_score += best_match_score
                                    logger.log("INFO", "SSDeep", f"Added SSDeep match to reasons. Total score now: {total_score}")
                                else:
                                    logger.log("DEBUG", "SSDeep", f"No SSDeep match (best: {best_match_score}%, threshold: 50%)")
                            else:
                                logger.log("DEBUG", "SSDeep", "Failed to generate SSDeep hash (empty result)")
                        except Exception as e:
                            # SSDeep hashing failed
                            logger.log("WARNING", "SSDeep", f"SSDeep check failed for {filePath}: {str(e)}")

                    # Yara Check -------------------------------------------------------
                    # Scan the read data với timeout protection (20 giây)
                    YARA_SCAN_TIMEOUT = 20.0  # 20 giây timeout cho YARA scan
                    yara_scan_start_time = time.time()
                    
                    try:
                        # Sử dụng queue để lấy kết quả từ thread
                        result_queue = queue.Queue()
                        exception_queue = queue.Queue()
                        
                        def yara_scan_worker():
                            """Worker function để chạy YARA scan trong thread riêng"""
                            try:
                                matches_list = []
                                for (score, rule, description, reference, matched_strings, author) in \
                                        self.scan_data(fileData=fileData,
                                                       fileType=fileType,
                                                       fileName=fileNameCleaned,
                                                       filePath=filePathCleaned,
                                                       extension=extension,
                                                       md5=md5  # legacy rule support
                                                       ):
                                    matches_list.append((score, rule, description, reference, matched_strings, author))
                                result_queue.put(matches_list)
                            except Exception as e:
                                exception_queue.put(e)
                        
                        # Chạy YARA scan trong thread riêng
                        scan_thread = threading.Thread(target=yara_scan_worker, daemon=True)
                        scan_thread.start()
                        
                        # Đợi thread hoàn thành hoặc timeout (20 giây)
                        scan_thread.join(timeout=YARA_SCAN_TIMEOUT)
                        
                        # Kiểm tra xem thread có còn chạy không
                        if scan_thread.is_alive():
                            # Thread vẫn chạy, có nghĩa là timeout
                            elapsed_time = time.time() - yara_scan_start_time
                            yara_timeout_occurred = True
                            timeout_message = f"YARA SCAN TIMEOUT: YARA rule matching exceeded {YARA_SCAN_TIMEOUT}s (actual: {elapsed_time:.2f}s). File requires manual review."
                            logger.log("WARNING", "FileScan", 
                                      f"YARA scan timeout ({elapsed_time:.2f}s > {YARA_SCAN_TIMEOUT}s) for file: {filePath}")
                            # Thêm thông tin timeout vào reasons để ghi vào output
                            reasons.append(timeout_message)
                        else:
                            # Thread đã hoàn thành, lấy kết quả
                            if not exception_queue.empty():
                                exception = exception_queue.get()
                                raise exception
                            
                            if not result_queue.empty():
                                yara_matches = result_queue.get()
                                
                                # Xử lý kết quả YARA
                                for (score, rule, description, reference, matched_strings, author) in yara_matches:
                                    # Message
                                    message = "Yara Rule MATCH: %s SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s" % \
                                              (rule, score, description, reference, author)
                                    # Matches
                                    if matched_strings:
                                        message += " MATCHES: %s" % matched_strings

                                    total_score += score
                                    reasons.append(message)

                    except Exception as e:
                        logger.log("ERROR", "FileScan", f"Cannot YARA scan file: {filePathCleaned}. Error: {str(e)}")

                    # Info Line -----------------------------------------------------------------------
                    # Nếu YARA timeout, vẫn ghi vào output để đánh giá thủ công
                    # Thêm flag vào fileInfo nếu có YARA timeout
                    fileInfo = "===========================================================\n" \
                               "FILE: %s\n SCORE: %s%s\n " % (
                                   filePath, total_score, getAgeString(filePath))
                    if yara_timeout_occurred:
                        fileInfo += "*** YARA SCAN TIMEOUT - REQUIRES MANUAL REVIEW ***\n "
                    
                    message_type = "INFO"
                    # Now print the total result
                    if total_score >= 100:
                        message_type = "ALERT"
                    elif total_score >= 60:
                        message_type = "WARNING"
                    elif total_score >= 40:
                        message_type = "NOTICE"
                    # Nếu YARA timeout, đánh dấu là WARNING để dễ nhận biết
                    if yara_timeout_occurred and message_type == "INFO":
                        message_type = "WARNING"

                    # Nếu YARA timeout, vẫn ghi vào output ngay cả khi score < 40
                    logger.log("DEBUG", "FileScan", f"File {filePath}: total_score={total_score}, reasons_count={len(reasons)}, yara_timeout={yara_timeout_occurred}")
                    if total_score < 40 and not yara_timeout_occurred:
                        logger.log("DEBUG", "FileScan", f"Skipping file {filePath} (score {total_score} < 40)")
                        continue

                    # Reasons to message body (tối ưu: dùng list join thay vì string concatenation)
                    message_body = fileInfo
                    reason_lines = []
                    reason_csv_lines = []
                    for i, r in enumerate(reasons):
                        reason_lines.append("\tREASON_{0}: {1}\n ".format(i + 1, r))
                        reason_csv_lines.append("REASON_{0}: {1}\n ".format(i + 1, r))
                    message_body += "".join(reason_lines)
                    message_csv = "".join(reason_csv_lines)
                    logger.log("DEBUG", "FileScan", f"Adding file to report: {filePath}, score={total_score}, message_type={message_type}, reasons={len(reasons)}")
                    
                    # Quarantine logic: move file nếu có quarantine flag và file có score >= 100 (ALERT)
                    if args and args.quarantine and total_score >= 100:
                        src = filePath
                        filename = os.path.basename(filePath.replace("/", os.sep)) + "." + str(int(time.time()))
                        quarantine_dir = os.path.join(self.app_path, "quarantine")
                        
                        # Tạo thư mục quarantine nếu chưa tồn tại
                        try:
                            if not os.path.exists(quarantine_dir):
                                os.makedirs(quarantine_dir)
                                logger.log("INFO", "FileScan", f"Created quarantine directory: {quarantine_dir}")
                        except Exception as e:
                            logger.log("ERROR", "FileScan", f"Cannot create quarantine directory {quarantine_dir}: {e}")
                            message_body += "FILE CAN NOT MOVED TO QUARANTINE (cannot create directory)!!!\n "
                        else:
                            dst = os.path.join(quarantine_dir, filename)
                            try:
                                # Kiểm tra file có tồn tại không trước khi move
                                if os.path.exists(src):
                                    shutil.move(src, dst)
                                    message_body += "FILE MOVED TO QUARANTINE: %s\n " % dst
                                else:
                                    logger.log("WARNING", "FileScan", f"Source file does not exist: {src}")
                                    message_body += "FILE CAN NOT MOVED TO QUARANTINE (source file not found)!!!\n "
                            except Exception as e:
                                logger.log("ERROR", "FileScan", f"Cannot move file to quarantine {src} -> {dst}: {e}")
                                message_body += "FILE CAN NOT MOVED TO QUARANTINE!!!\n "
                    MESSAGE.append([total_score, message_type, message_body])
                    fileInfo_csv["FILE"].append(filePath)
                    fileInfo_csv["SCORE"].append(total_score)
                    fileInfo_csv["TIME"].append(getAgeString(filePath))
                    fileInfo_csv["DESCRIPTION"].append(message_csv)
                    fileInfo_csv["EXTENSION"].append(extension)
                    logger.log("DEBUG", "FileScan", f"Added to MESSAGE and CSV: {filePath}, score={total_score}, has_ssdeep={any('SSDeep' in r for r in reasons)}")
                except Exception as e:
                    logger.log("ERROR", "FileScan", f"Error processing file {filePath}: {str(e)}")
                    traceback.print_exc()
        MESSAGE.sort(key=lambda x: x[0], reverse=True)
        logger.log("INFO", "FileScan", f"Total files to report: {len(MESSAGE)}")
        # Log individual files - DEBUG messages won't print to console
        for i in MESSAGE:
            # Use log() - DEBUG won't print to console, other types will
            logger.log(i[1], "FileScan", i[2])
            # Debug: log summary to see what's being written (file only)
            # Removed - no longer needed

    def scan_data(self, fileData, fileType="-", fileName=b"-", filePath=b"-", extension=b"-", md5="-"):
        """
        Scan dữ liệu file với YARA rules.
        Tối ưu: decode một lần và tái sử dụng externals dict.
        """
        # Decode filename và filepath một lần (tối ưu)
        try:
            filename_str = fileName.decode('utf-8') if isinstance(fileName, bytes) else fileName
            filepath_str = filePath.decode('utf-8') if isinstance(filePath, bytes) else filePath
        except (UnicodeDecodeError, AttributeError):
            # Fallback nếu decode thất bại
            filename_str = str(fileName) if not isinstance(fileName, str) else fileName
            filepath_str = str(filePath) if not isinstance(filePath, str) else filePath
        
        # Tạo externals dict một lần (tối ưu)
        externals = {
            'filename': filename_str,
            'filepath': filepath_str,
            'extension': extension,
            'filetype': fileType,
            'md5': md5,
            'owner': "dummy"
        }
        
        # Scan with yara
        try:
            for rules in self.yara_rules:
                # Yara Rule Match
                matches = rules.match(data=fileData, externals=externals)

                # If matched
                if matches:
                    for match in matches:
                        score = 70
                        description = "not set"
                        reference = "-"
                        author = "-"

                        # Built-in rules have meta fields (cannot be expected from custom rules)
                        if hasattr(match, 'meta'):
                            meta = match.meta  # Cache để tránh truy cập nhiều lần
                            
                            if 'description' in meta:
                                description = meta['description']
                            if 'cluster' in meta:
                                description = "IceWater Cluster {0}".format(meta['cluster'])

                            if 'reference' in meta:
                                reference = meta['reference']
                            if 'viz_url' in meta:
                                reference = meta['viz_url']
                            if 'author' in meta:
                                author = meta['author']

                            # If a score is given
                            if 'score' in meta:
                                score = int(meta['score'])

                        # Matching strings
                        matched_strings = ""
                        if hasattr(match, 'strings'):
                            # Get matching strings
                            matched_strings = self.get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except Exception as e:
            logger.log("DEBUG", "YARA", f"Error during YARA scan: {str(e)}")
            pass

    def initialize_filename_iocs(self, ioc_directory):
        """Initialize filename IOCs from directory. This function is kept for backward compatibility but is currently disabled."""
        # NOTE: This function is currently disabled. Filename IOCs are loaded via initialize_filename_iocs_from_file instead.
        # If you need to re-enable this, remove the return statement below.
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

    @staticmethod
    def extract_line_number_from_error(error_msg):
        """
        Extract số dòng từ YARA error message.
        Ví dụ: "line 209423: invalid field name" -> 209423
        """
        match = re.search(r'line\s+(\d+):', str(error_msg), re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None
    
    @staticmethod
    def print_error_line_context(source_text, line_number, context_lines=3):
        """
        In ra dòng lỗi cùng với context xung quanh.
        """
        if not source_text or line_number is None:
            return
        
        lines = source_text.split('\n')
        total_lines = len(lines)
        
        # Đảm bảo line_number hợp lệ (1-based index)
        if line_number < 1 or line_number > total_lines:
            return
        
        # Tính toán range để in
        start_line = max(1, line_number - context_lines)
        end_line = min(total_lines, line_number + context_lines)
        
        # In ra context
        print("\n" + "="*80)
        print(f"ERROR LINE {line_number} CONTEXT:")
        print("="*80)
        for i in range(start_line - 1, end_line):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            line_content = lines[i] if i < len(lines) else ""
            print(f"{prefix}Line {line_num:6d}: {line_content}")
        print("="*80 + "\n")

    def initialize_yara_rules(self):
        """
        Khởi tạo và biên dịch YARA rules.
        Biên dịch toàn bộ rules cùng lúc.
        """
        # Externals cho YARA compilation
        dummy = ""
        YARA_EXTERNALS = {
            'filename': dummy,
            'filepath': dummy,
            'extension': dummy,
            'filetype': dummy,
            'md5': dummy,
            'owner': dummy,
        }
        
        # Extension hợp lệ
        VALID_EXTENSIONS = {'.yar', '.yara'}
        
        # Prefix cần skip
        SKIP_PREFIXES = ('.', '~', '_')
        
        yara_rule_contents = []
        total_files = 0

        try:
            # Bước 1: Thu thập tất cả các file YARA rules
            for yara_rule_directory in self.yara_rule_directories:
                if not os.path.exists(yara_rule_directory):
                    continue
                
                for root, directories, files in os.walk(yara_rule_directory, onerror=self.walk_error,
                                                        followlinks=False):
                    for file in files:
                        # Skip hidden, backup or system related files (tối ưu check)
                        if not file or file[0] in SKIP_PREFIXES:
                            continue

                        # Extension check (tối ưu)
                        extension = os.path.splitext(file)[1].lower()
                        if extension not in VALID_EXTENSIONS:
                            continue

                        # Full Path
                        yaraRuleFile = os.path.join(root, file)

                        # Đọc nội dung file
                        try:
                            with open(yaraRuleFile, 'r', encoding='utf-8', errors='replace') as yfile:
                                yara_rule_data = yfile.read()
                            
                            if yara_rule_data.strip():  # Chỉ thêm file không rỗng
                                yara_rule_contents.append(yara_rule_data)
                                total_files += 1
                                
                        except UnicodeDecodeError:
                            logger.log("WARNING", "Init", 
                                      f"Cannot read file {file} - encoding error, skipping")
                            continue
                        except Exception as e:
                            logger.log("WARNING", "Init",
                                      f"Error reading signature file {file}: {str(e)}")
                            continue

            if not yara_rule_contents:
                logger.log("ERROR", "Init", "No YARA rule files found!")
                sys.exit(1)

            logger.log("INFO", "Init", f"Found {total_files} YARA rule file(s)")

            # Biên dịch toàn bộ rules cùng lúc
            yaraRules = '\n'.join(yara_rule_contents)
            
            try:
                logger.log("INFO", "Init", "Compiling all YARA rules together...")
                compiledRules = yara.compile(source=yaraRules, externals=YARA_EXTERNALS)
                
                # Đếm số rules đã biên dịch
                total_rules = len(re.findall(r'^\s*rule\s+', yaraRules, re.MULTILINE))
                
                self.yara_rules.append(compiledRules)
                logger.log("INFO", "Init", 
                          f"Successfully compiled all YARA rules together: {total_rules} rule(s) from {total_files} file(s)")

            except yara.SyntaxError as e:
                error_msg = str(e)
                logger.log("ERROR", "Init", 
                          f"Failed to compile all YARA rules together: {error_msg}")
                
                # Extract và in ra dòng lỗi
                line_number = self.extract_line_number_from_error(error_msg)
                if line_number:
                    self.print_error_line_context(yaraRules, line_number)
                
                logger.log("ERROR", "Init", 
                          "Please fix the YARA rule errors and try again.")
                sys.exit(1)
            except Exception as e:
                error_msg = str(e)
                logger.log("ERROR", "Init", 
                          f"Unexpected error during YARA compilation: {error_msg}")
                
                # Extract và in ra dòng lỗi nếu có
                line_number = self.extract_line_number_from_error(error_msg)
                if line_number:
                    self.print_error_line_context(yaraRules, line_number)
                
                logger.log("ERROR", "Init", 
                          "Please fix the YARA rule errors and try again.")
                sys.exit(1)

        except Exception as e:
            logger.log("ERROR", "Init", f"Critical error during YARA rule initialization: {str(e)}")
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

    def initialize_filename_iocs_from_file(self, ioc_file):
        """Đọc filename IOCs từ một file cụ thể."""
        try:
            with codecs.open(ioc_file, 'r', encoding='utf-8') as file:
                lines = file.readlines()

                last_comment = ""
                score = 0
                desc = ""

                for line in lines:
                    try:
                        if re.search(r'^\s*$', line):
                            continue

                        if re.search(r'^#', line):
                            last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                            continue

                        regex_fp = None
                        if ";" in line:
                            line = line.rstrip(" ").rstrip("\n\r")
                            row = line.split(';')
                            regex = row[0]
                            score = row[1]
                            if len(row) > 2:
                                regex_fp = row[2]
                            desc = last_comment
                        else:
                            regex = line

                        regex = replaceEnvVars(regex)
                        regex = transformOS(regex, os_platform)

                        regex_fp_comp = None
                        if regex_fp:
                            regex_fp = replaceEnvVars(regex_fp)
                            regex_fp = transformOS(regex_fp, os_platform)
                            regex_fp_comp = re.compile(regex_fp)

                        fioc = {'regex': re.compile(regex), 'score': score, 'description': desc,
                                'regex_fp': regex_fp_comp}
                        self.filename_iocs.append(fioc)

                    except Exception:
                        logger.log("ERROR", "Init", "Error reading line: %s" % line)
        except Exception as e:
            logger.log("WARNING", "Init", f"Error reading custom IOC file {ioc_file}: {str(e)}")

    def initialize_hash_iocs_from_file(self, ioc_file, false_positive=False):
        """Đọc hash IOCs từ một file cụ thể."""
        HASH_WHITELIST = [
            int('d41d8cd98f00b204e9800998ecf8427e', 16),
            int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16),
            int('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 16),
            int('68b329da9893e34099c7d8ad5cb9c940', 16),
            int('adc83b19e793491b1c6ea0fd8b46cd9f32e592fc', 16),
            int('01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', 16),
            int('81051bcc2cf1bedf378224b0a93e2877', 16),
            int('ba8ab5a0280b953aa97435ff8946cbcbb2755a27', 16),
            int('7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6', 16),
        ]
        try:
            with codecs.open(ioc_file, 'r', encoding='utf-8') as file:
                lines = file.readlines()

                for line in lines:
                    try:
                        if re.search(r'^#', line) or re.search(r'^\s*$', line):
                            continue
                        row = line.split(';')
                        file_hash = row[0].lower()
                        comment = row[1].rstrip(" ").rstrip("\n")
                        if file_hash in HASH_WHITELIST:
                            continue
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
            
            # Update sorted lists
            self.hashes_md5_list = list(self.hashes_md5.keys())
            self.hashes_md5_list.sort()
            self.hashes_sha1_list = list(self.hashes_sha1.keys())
            self.hashes_sha1_list.sort()
            self.hashes_sha256_list = list(self.hashes_sha256.keys())
            self.hashes_sha256_list.sort()
        except Exception as e:
            logger.log("WARNING", "Init", f"Error reading custom hash IOC file {ioc_file}: {str(e)}")

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

    def initialize_filetype_magics_from_file(self, filetype_magics_file):
        """Đọc file type magic signatures từ một file cụ thể."""
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

                    self.filetype_magics[sig] = description

                except Exception:
                    logger.log("ERROR", "Init", "Cannot read line: %s" % line)

        except Exception as e:
            logger.log("WARNING", "Init", f"Error reading custom misc file {filetype_magics_file}: {str(e)}")

    def initialize_ssdeep_signatures(self, ssdeep_file):
        """Đọc SSDeep signatures từ file known_webshells.ssdeep."""
        if ssdeep is None:
            logger.log("WARNING", "Init", "pyssdeep module not installed. SSDeep checking will be disabled.")
            logger.log("WARNING", "Init", "Install pyssdeep with: pip install pyssdeep")
            return
        
        try:
            with open(ssdeep_file, 'r', encoding='utf-8', errors='replace') as file:
                lines = file.readlines()

            # Skip header line if present
            for line in lines:
                try:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Skip header line (format: ssdeep,1.1--blocksize:hash:hash,filename)
                    if line.startswith('ssdeep,'):
                        continue
                    
                    # Parse SSDeep format: blocksize:hash1:hash2,filename
                    if ',' not in line:
                        continue
                    
                    # Split by comma to separate hash and filename
                    parts = line.split(',', 1)
                    if len(parts) != 2:
                        continue
                    
                    ssdeep_hash = parts[0].strip()
                    filename = parts[1].strip().strip('"').strip("'")
                    
                    # Validate SSDeep hash format (should contain ':')
                    if ':' not in ssdeep_hash:
                        continue
                    
                    # Store as tuple: (ssdeep_hash, filename)
                    self.ssdeep_signatures.append((ssdeep_hash, filename))

                except Exception:
                    logger.log("ERROR", "Init", "Cannot read SSDeep line: %s" % line)
                    
        except Exception as e:
            logger.log("WARNING", "Init", f"Error reading SSDeep file {ssdeep_file}: {str(e)}")

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

    @staticmethod
    def get_application_path():
        try:
            if getattr(sys, 'frozen', False):
                application_path = os.path.dirname(os.path.realpath(sys.executable))
            else:
                application_path = os.path.dirname(os.path.realpath(__file__))
            return application_path
        except Exception as e:
            error_msg = f"Error while evaluation of application path: {str(e)}"
            print(error_msg)
            if 'logger' in globals():
                logger.log("ERROR", "Init", error_msg)
            traceback.print_exc()
            sys.exit(1)

    @staticmethod
    def walk_error(err):
        if "Error 3" in str(err):
            error_msg = f"Directory walk error: {str(err)}"
            print(error_msg)
            if 'logger' in globals():
                logger.log("WARNING", "FileScan", error_msg)


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    try:
        print("------------------------------------------------------------------------------\n")
    except Exception:
        pass
    sys.exit(0)


def main():
    # Generate default log filename: scan_ip_date_time.log
    hostname = getHostname(os_platform)
    ip = getLocalIP()
    
    # Clean hostname: remove .localdomain, .local, or use short name
    if hostname and '.' in hostname:
        # Take first part before dot, or use full if it's short
        hostname_parts = hostname.split('.')
        if hostname_parts[0] in ['localhost', 'local']:
            hostname_clean = ''  # Skip hostname for localhost
        else:
            hostname_clean = hostname_parts[0]
    else:
        hostname_clean = hostname if hostname and hostname not in ['localhost', 'local'] else ''
    
    # Keep IP with dots for readability (filesystems support dots)
    ip_clean = ip if ip else 'unknown'
    
    # Format time as YYYY-MM-DD_HH-MM-SS for better readability
    time_str = time.strftime("%Y-%m-%d_%H-%M-%S")
    
    # Parse Arguments
    parser = argparse.ArgumentParser(description='WebShell Scanner')
    parser.add_argument('-p', '--path', help='Path to scan', required=True)
    parser.add_argument('-o', '--out_file', help='Write to file', default=None)
    parser.add_argument('-q', '--quarantine', help='Rename and move to quarantine areas', default=False,
                        action='store_true')
    parser.add_argument('-d', '--debug', help='Enable debug mode to show all DEBUG messages on console', 
                        default=False, action='store_true')
    args = parser.parse_args()
    
    # Nếu không chỉ định --out_file, tạo tên file log với tên thư mục được quét
    if args.out_file is None:
        try:
            # Lấy tên thư mục từ path được quét
            scan_path = os.path.normpath(args.path).rstrip(os.sep)
            
            # Xác định tên thư mục: nếu path là file thì lấy thư mục chứa file, nếu là directory thì lấy tên directory
            if os.path.isfile(scan_path):
                # Path là file, lấy tên thư mục chứa file
                scan_dir_name = os.path.basename(os.path.dirname(scan_path))
            else:
                # Path là directory, lấy tên directory
                scan_dir_name = os.path.basename(scan_path)
            
            # Xử lý trường hợp root directory hoặc tên rỗng
            if not scan_dir_name:
                # Nếu là root directory, thử lấy phần cuối của path
                path_parts = [p for p in scan_path.split(os.sep) if p]
                if path_parts:
                    scan_dir_name = path_parts[-1]
                else:
                    scan_dir_name = 'root'
            
            # Làm sạch tên thư mục: bỏ ký tự đặc biệt, giới hạn độ dài
            # Thay thế các ký tự không hợp lệ trong tên file
            invalid_chars = '<>:"/\\|?*'
            for char in invalid_chars:
                scan_dir_name = scan_dir_name.replace(char, '_')
            
            # Giới hạn độ dài tên thư mục (tránh tên file quá dài)
            max_dir_name_length = 30
            if len(scan_dir_name) > max_dir_name_length:
                scan_dir_name = scan_dir_name[:max_dir_name_length]
            
            # Tạo tên file log mới với tên thư mục
            if hostname_clean:
                default_log_file = f"scan_{hostname_clean}-{ip_clean}_{scan_dir_name}_{time_str}.log"
            else:
                default_log_file = f"scan_{ip_clean}_{scan_dir_name}_{time_str}.log"
        except Exception:
            # Fallback: sử dụng tên file log mặc định không có tên thư mục
            if hostname_clean:
                default_log_file = f"scan_{hostname_clean}-{ip_clean}_{time_str}.log"
            else:
                default_log_file = f"scan_{ip_clean}_{time_str}.log"
        
        args.out_file = default_log_file

    return args


# MAIN ################################################################
if __name__ == '__main__':

    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Argument parsing
    args = main()

    # Logger
    logger = Logger(getHostname(os_platform),
                    platform=os_platform, caller='main', VERSION=VERSION, log_file=args.out_file, 
                    debug_mode=args.debug)

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
    scanner.scan_path(defaultPath, args=args)

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
