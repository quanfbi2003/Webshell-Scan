# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import argparse
import codecs
import os
import re
import shutil
import signal as signal_module
import stat
import sys
import time
import threading
import queue
import multiprocessing
from multiprocessing import Process, Queue, Manager, Lock
import traceback
import uuid
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

from libs.scan_policy import load_scan_policy, apply_cli_overrides
from libs.deobfuscate import iter_deobfuscated_layers, should_deobfuscate
from libs.heuristics import (
    behavior_graph_heuristic,
    entropy_heuristic,
    library_fp_gate,
    source_sink_heuristic,
    webshell_capability_heuristic,
)
from libs.scan_health import (
    ScanStats, run_preflight_checks, log_preflight_summary, log_runtime_summary,
    STATUS_ERROR,
)
from libs import ssdeep_db
from libs.vt_browser import prompt_browser_verdict
from libs.review_bundle import build_review_zip, bundle_passphrase, write_review_bundle

# For Windows
try:
    from win32comext.shell import shell
except:
    shell = None

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

# Báo cáo Excel — mọi báo cáo đều có cột SHA256 (ngay sau FILE)
FINDINGS_REPORT_COLUMNS = ["FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION"]
ALL_FILES_REPORT_COLUMNS = ["FILE", "SHA256", "TIME_CREATED", "TIME_MODIFIED", "TIME_ACCESSED", "EXTENSION"]
GRAY_ZONE_REPORT_COLUMNS = [
    "FILE", "SHA256", "SCORE", "TIME", "DESCRIPTION", "EXTENSION",
    "VIRUSTOTAL_URL", "VT_CHECKED", "VT_RESULT",
]

fileInfo_csv = {col: [] for col in FINDINGS_REPORT_COLUMNS}
all_files_csv = {col: [] for col in ALL_FILES_REPORT_COLUMNS}
gray_zone_csv = {col: [] for col in GRAY_ZONE_REPORT_COLUMNS}


def new_findings_report():
    return {col: [] for col in FINDINGS_REPORT_COLUMNS}


def new_all_files_report():
    return {col: [] for col in ALL_FILES_REPORT_COLUMNS}


def new_gray_zone_report():
    return {col: [] for col in GRAY_ZONE_REPORT_COLUMNS}


class BenignFileFilter(object):
    METADATA_FILENAMES = {".ds_store", ".gitattributes", ".gitignore", "authors"}
    NON_WEBSHELL_EXTENSIONS = {
        ".bmp", ".cap", ".dsa", ".emf", ".fit", ".glb", ".hbs", ".jsx", ".list",
        ".lock", ".md", ".mdx", ".me", ".request", ".rsa", ".suo", ".ts", ".tsx",
        ".wmf",
        ".html@c=d;o=a", ".html@c=d;o=d", ".html@c=m;o=a", ".html@c=m;o=d",
        ".html@c=n;o=a", ".html@c=n;o=d", ".html@c=s;o=a", ".html@c=s;o=d",
    }
    ICU_DATA_EXTENSIONS = {".brk", ".dict", ".icu", ".nrm"}

    def is_metadata_file(self, file_path):
        return os.path.basename(file_path).lower() in self.METADATA_FILENAMES

    def is_non_webshell_file(self, file_path):
        return os.path.splitext(file_path)[1].lower() in self.NON_WEBSHELL_EXTENSIONS

    def is_icu_data_file(self, file_path, file_data):
        extension = os.path.splitext(file_path)[1].lower()
        if extension not in self.ICU_DATA_EXTENSIONS:
            return False
        if not file_data or len(file_data) < 4:
            return False
        # ICU binary data has a DataHeader magic DA 27, commonly at bytes 2..3.
        return file_data[:2] == b"\xDA\x27" or file_data[2:4] == b"\xDA\x27"


class SafeArchiveExtractor(object):
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
                          '.war', '.jar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
                          '.tar.xz', '.txz', '.ear', '.sar', '.nar'}
    MAX_ARCHIVE_SIZE = 20 * 1024 * 1024  # 20MB
    MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200MB
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB per extracted member
    MAX_FILES = 5000
    MAX_DEPTH = 5

    def is_archive_file(self, file_path):
        file_path_lower = file_path.lower()
        for ext in sorted(self.ARCHIVE_EXTENSIONS, key=len, reverse=True):
            if file_path_lower.endswith(ext):
                return True, ext
        return False, None

    def member_destination(self, archive_temp_dir, member_name):
        safe_root = os.path.realpath(archive_temp_dir)
        dst = os.path.realpath(os.path.join(archive_temp_dir, member_name))
        try:
            if os.path.commonpath([safe_root, dst]) != safe_root:
                return None
        except ValueError:
            return None
        return dst

    def check_budget(self, state, member_size, archive_path):
        if state["files"] + 1 > self.MAX_FILES:
            logger.log("WARNING", "Archive",
                       f"Archive file count limit exceeded ({self.MAX_FILES}): {archive_path}")
            return False
        if member_size > self.MAX_FILE_SIZE:
            logger.log("WARNING", "Archive",
                       f"Archive member too large ({member_size} > {self.MAX_FILE_SIZE}): {archive_path}")
            return False
        if state["bytes"] + member_size > self.MAX_TOTAL_UNCOMPRESSED:
            logger.log("WARNING", "Archive",
                       "Archive uncompressed size limit exceeded "
                       f"({state['bytes'] + member_size} > {self.MAX_TOTAL_UNCOMPRESSED}): {archive_path}")
            return False
        state["files"] += 1
        state["bytes"] += member_size
        return True

    def copy_stream_limited(self, src, dst, state, archive_path):
        bytes_written = 0
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'wb') as out_file:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > self.MAX_FILE_SIZE:
                    raise ValueError("archive member exceeds per-file size limit")
                if state["bytes"] + bytes_written > self.MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError("archive exceeds total uncompressed size limit")
                out_file.write(chunk)
        if not self.check_budget(state, bytes_written, archive_path):
            try:
                os.remove(dst)
            except Exception:
                pass
            return False
        return True

    def collect_extracted_files_with_budget(self, archive_temp_dir, archive_path):
        extracted_files = []
        total_size = 0
        safe_root = os.path.realpath(archive_temp_dir)
        for root, dirs, files in os.walk(archive_temp_dir):
            root_real = os.path.realpath(root)
            try:
                if os.path.commonpath([safe_root, root_real]) != safe_root:
                    continue
            except ValueError:
                continue
            for file in files:
                path = os.path.join(root, file)
                path_real = os.path.realpath(path)
                try:
                    if os.path.commonpath([safe_root, path_real]) != safe_root:
                        logger.log("WARNING", "Archive", f"Skipping unsafe extracted path: {path}")
                        continue
                    size = os.path.getsize(path_real)
                except Exception:
                    continue
                if len(extracted_files) + 1 > self.MAX_FILES:
                    logger.log("WARNING", "Archive",
                               f"Archive file count limit exceeded ({self.MAX_FILES}): {archive_path}")
                    return extracted_files
                if size > self.MAX_FILE_SIZE:
                    logger.log("WARNING", "Archive",
                               f"Skipping oversized extracted file ({size} bytes): {path_real}")
                    continue
                if total_size + size > self.MAX_TOTAL_UNCOMPRESSED:
                    logger.log("WARNING", "Archive",
                               f"Archive uncompressed size limit exceeded: {archive_path}")
                    return extracted_files
                total_size += size
                extracted_files.append(path_real)
        return extracted_files

    def extract(self, archive_path, temp_dir):
        extracted_files = []
        try:
            is_archive, ext = self.is_archive_file(archive_path)
            if not is_archive:
                return extracted_files

            logger.log("DEBUG", "Archive", f"Extracting archive: {archive_path} (type: {ext})")

            archive_temp_dir = os.path.join(
                temp_dir,
                os.path.basename(archive_path) + "_" + uuid.uuid4().hex + "_extracted")
            os.makedirs(archive_temp_dir, exist_ok=True)
            archive_budget = {"files": 0, "bytes": 0}

            if ext in ['.zip', '.jar', '.war', '.ear', '.sar', '.nar']:
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        for member in zip_ref.infolist():
                            if member.is_dir():
                                continue
                            extracted_path = self.member_destination(archive_temp_dir, member.filename)
                            if not extracted_path:
                                logger.log("WARNING", "Archive",
                                           f"Skipping unsafe ZIP member path: {member.filename}")
                                continue
                            member_size = int(member.file_size or 0)
                            if not self.check_budget(archive_budget, member_size, archive_path):
                                break
                            os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                            with zip_ref.open(member, 'r') as src, open(extracted_path, 'wb') as out_file:
                                shutil.copyfileobj(src, out_file)
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
                        for member in tar_ref.getmembers():
                            if not member.isfile():
                                continue
                            extracted_path = self.member_destination(archive_temp_dir, member.name)
                            if not extracted_path:
                                logger.log("WARNING", "Archive",
                                           f"Skipping unsafe TAR member path: {member.name}")
                                continue
                            member_size = int(member.size or 0)
                            if not self.check_budget(archive_budget, member_size, archive_path):
                                break
                            src = tar_ref.extractfile(member)
                            if src is None:
                                continue
                            os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                            with src, open(extracted_path, 'wb') as out_file:
                                shutil.copyfileobj(src, out_file)
                            if os.path.isfile(extracted_path):
                                extracted_files.append(extracted_path)
                except tarfile.TarError as e:
                    logger.log("WARNING", "Archive", f"Error extracting TAR file {archive_path}: {str(e)}")
                    return extracted_files

            elif ext == '.gz':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-3])
                    with gzip.open(archive_path, 'rb') as gz_ref:
                        if self.copy_stream_limited(gz_ref, output_path, archive_budget, archive_path):
                            extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting GZ file {archive_path}: {str(e)}")
                    return extracted_files

            elif ext == '.bz2':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-4])
                    with bz2.open(archive_path, 'rb') as bz2_ref:
                        if self.copy_stream_limited(bz2_ref, output_path, archive_budget, archive_path):
                            extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting BZ2 file {archive_path}: {str(e)}")
                    return extracted_files

            elif ext == '.xz':
                try:
                    output_path = os.path.join(archive_temp_dir, os.path.basename(archive_path)[:-3])
                    with lzma.open(archive_path, 'rb') as xz_ref:
                        if self.copy_stream_limited(xz_ref, output_path, archive_budget, archive_path):
                            extracted_files.append(output_path)
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error extracting XZ file {archive_path}: {str(e)}")
                    return extracted_files

            elif ext in ['.rar', '.7z']:
                try:
                    result = subprocess.run(['7z', '--help'], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        cmd = ['7z', 'x', archive_path, f'-o{archive_temp_dir}', '-y']
                        result = subprocess.run(cmd, capture_output=True, timeout=60)
                        if result.returncode == 0:
                            extracted_files.extend(
                                self.collect_extracted_files_with_budget(archive_temp_dir, archive_path))
                        else:
                            logger.log("WARNING", "Archive", f"7z extraction failed for {archive_path}")
                    else:
                        logger.log("WARNING", "Archive",
                                   f"7z tool not available, cannot extract {ext} file: {archive_path}")
                except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                    logger.log("WARNING", "Archive", f"Cannot extract {ext} file {archive_path}: {str(e)}")

            logger.log("DEBUG", "Archive", f"Extracted {len(extracted_files)} files from {archive_path}")
            return extracted_files

        except Exception as e:
            logger.log("ERROR", "Archive", f"Error extracting archive {archive_path}: {str(e)}")
            return extracted_files


class QuarantineManager(object):
    def __init__(self, app_path, lock):
        self.app_path = app_path
        self.lock = lock

    def build_exact_path(self, quarantine_dir, src, sha256):
        fname = os.path.basename(src.replace("/", os.sep))
        dst = os.path.join(quarantine_dir, fname)

        if not os.path.exists(dst):
            return dst

        dst_sha256 = "0"
        try:
            with open(dst, "rb") as fh:
                _, _, dst_sha256 = generateHashes(fh.read(), logger)
        except Exception:
            dst_sha256 = "0"

        if dst_sha256 == sha256:
            try:
                os.remove(dst)
            except Exception:
                pass
            return dst

        name, ext = os.path.splitext(fname)
        dst = os.path.join(quarantine_dir, "%s_%s%s" % (name, sha256[:8], ext))
        counter = 2
        while os.path.exists(dst):
            existing_sha256 = "0"
            try:
                with open(dst, "rb") as fh:
                    _, _, existing_sha256 = generateHashes(fh.read(), logger)
            except Exception:
                existing_sha256 = "0"
            if existing_sha256 == sha256:
                try:
                    os.remove(dst)
                except Exception:
                    pass
                return dst
            dst = os.path.join(quarantine_dir, "%s_%s_%s%s" % (name, sha256[:8], counter, ext))
            counter += 1

        return dst

    def move(self, src, sha256, exact=False):
        quarantine_dir = os.path.join(self.app_path, "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        with self.lock:
            if exact:
                dst = self.build_exact_path(quarantine_dir, src, sha256)
            else:
                filename_only = os.path.basename(src.replace("/", os.sep)) + "." + str(int(time.time() * 1000000))
                dst = os.path.join(quarantine_dir, filename_only)
            if not os.path.exists(src):
                return None, "source_missing"
            shutil.move(src, dst)
            return dst, None


class Scanner(object):
    # Class-level CONSTANTS only (immutable sets — safe to share)
    # Archive extraction settings
    ARCHIVE_EXTENSIONS = SafeArchiveExtractor.ARCHIVE_EXTENSIONS
    MAX_ARCHIVE_SIZE = SafeArchiveExtractor.MAX_ARCHIVE_SIZE
    MAX_ARCHIVE_TOTAL_UNCOMPRESSED = SafeArchiveExtractor.MAX_TOTAL_UNCOMPRESSED
    MAX_ARCHIVE_FILE_SIZE = SafeArchiveExtractor.MAX_FILE_SIZE
    MAX_ARCHIVE_FILES = SafeArchiveExtractor.MAX_FILES
    MAX_ARCHIVE_DEPTH = SafeArchiveExtractor.MAX_DEPTH

    # Predefined paths to skip (Linux platform)
    LINUX_PATH_SKIPS_START = {"/proc", "/dev", "/sys/kernel/debug", "/sys/kernel/slab", "/sys/devices",
                              "/usr/src/linux"}
    MOUNTED_DEVICES = {"/media", "/volumes"}
    LINUX_PATH_SKIPS_END = {"/initctl"}
    BENIGN_METADATA_FILENAMES = BenignFileFilter.METADATA_FILENAMES
    BENIGN_NON_WEBSHELL_EXTENSIONS = BenignFileFilter.NON_WEBSHELL_EXTENSIONS
    ICU_DATA_EXTENSIONS = BenignFileFilter.ICU_DATA_EXTENSIONS

    def __init__(self):
        # Get application path
        self.app_path = self.get_application_path()
        self.progress_lock = threading.Lock()
        self.result_lock = threading.Lock()
        self.quarantine_lock = threading.Lock()
        self.benign_filter = BenignFileFilter()
        self.archive_extractor = SafeArchiveExtractor()
        self.quarantine_manager = QuarantineManager(self.app_path, self.quarantine_lock)
        self.scan_stats = ScanStats()
        self.scan_stats.set_lock(self.result_lock)
        self.processed_files = 0
        # For multiprocessing
        self.use_multiprocessing = False
        self.mp_manager = None
        self.mp_progress_counter = None
        self.mp_result_queue = None

        # --- Instance-level mutable collections (NOT class-level to avoid sharing between instances) ---
        self.yara_rules = []
        self.filename_iocs = []
        self.hashes_md5 = {}
        self.hashes_sha1 = {}
        self.hashes_sha256 = {}
        self.false_hashes = {}
        self.ssdeep_signatures = []  # List of (ssdeep_hash, filename) tuples
        self.ssdeep_index = {}

        # Sorted hash lists for binary search
        self.hashes_md5_list = []
        self.hashes_sha1_list = []
        self.hashes_sha256_list = []

        # Yara rule directories (instance-level)
        self.yara_rule_directories = []

        # Excludes
        self.fullExcludes = []
        self.startExcludes = []

        # File type magics
        self.filetype_magics = {}
        self.max_filetype_magics = 0

        # Scan policy
        self.scan_policy = load_scan_policy(self.app_path, logger)
        self.effective_policy = dict(self.scan_policy)
        self.ssdeep_threshold = 50
        self.preflight_results = []

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
        filename_ioc_file = os.path.join(self.ioc_path, "filename-iocs.txt")
        if os.path.exists(filename_ioc_file):
            self.initialize_filename_iocs_from_file(filename_ioc_file)
        for custom_filename_file in self._custom_ioc_files("filename"):
            self.initialize_filename_iocs_from_file(custom_filename_file)
        logger.log("INFO", "Init",
                   "File Name Characteristics initialized with %s regex patterns" % len(self.filename_iocs))

        ## Hash based IOCs (all files in iocs that contain 'hash')
        self.initialize_hash_iocs(self.ioc_path)
        for custom_hash_file in self._custom_ioc_files("hash"):
            self.initialize_hash_iocs_from_file(custom_hash_file)
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

        self.ssdeep_threshold = int(self.scan_policy.get("ssdeep_threshold_default", 50))
        obfusc_yar = os.path.join(self.custom_path, "yara_obfuscate.yar")
        if os.path.isfile(obfusc_yar):
            logger.log("INFO", "Init", "Obfuscate YARA rules loaded from custom/yara_obfuscate.yar")

    def _custom_ioc_file_looks_like_hash(self, ioc_file):
        try:
            with codecs.open(ioc_file, 'r', encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    if re.search(r'^\s*(#|$)', line):
                        continue
                    token = line.split(';', 1)[0].strip().lower()
                    return bool(re.fullmatch(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}', token))
        except Exception as exc:
            logger.log("WARNING", "Init", "Cannot classify custom IOC file %s: %s" % (ioc_file, exc))
        return False

    def _custom_ioc_files(self, kind):
        if kind == "filename":
            names = ("filename-iocs.txt", "filename_iocs.txt", "iocs_filename.txt", "iocs_custom_filename.txt")
        elif kind == "hash":
            names = ("hash-iocs.txt", "hash_iocs.txt", "iocs_hash.txt", "iocs_custom_hash.txt")
        else:
            return []

        files = []
        for name in names:
            path = os.path.join(self.custom_path, name)
            if os.path.isfile(path):
                files.append(path)

        legacy = os.path.join(self.custom_path, "iocs_custom.txt")
        if os.path.isfile(legacy):
            legacy_is_hash = self._custom_ioc_file_looks_like_hash(legacy)
            if kind == "hash" and legacy_is_hash:
                files.append(legacy)
            elif kind == "filename" and not legacy_is_hash:
                files.append(legacy)

        deduped = []
        seen = set()
        for path in files:
            key = os.path.realpath(path).lower()
            if key not in seen:
                seen.add(key)
                deduped.append(path)
        return deduped

    def apply_runtime_policy(self, args):
        """Apply --min-score / --paranoid after CLI parsing."""
        self.effective_policy = apply_cli_overrides(self.scan_policy, args)
        self.ssdeep_threshold = int(self.effective_policy.get("ssdeep_threshold_effective", 50))
        logger.log(
            "INFO", "Init",
            "Scan policy: min_score=%s gray_zone>=%s ssdeep=%s ssdeep_threshold=%s deobfuscate=%s"
            % (
                self.effective_policy.get("min_score_effective"),
                self.effective_policy.get("gray_zone_min_score"),
                "enabled" if self.effective_policy.get("ssdeep_enabled_effective", True) else "disabled",
                self.ssdeep_threshold,
                self.effective_policy.get("deobfuscate_enabled", True),
            ),
        )
        vt_note = ""
        if self.effective_policy.get("vt_ssdeep_enabled"):
            vt_note = "; sau quét: mở VT trên trình duyệt → thêm SSDeep nếu báo mã độc"
        logger.log(
            "NOTICE", "Init",
            "Tự động mỗi lần quét: policy (config/scan-policy.json), YARA custom/obfuscate, "
            "deobfuscate+YARA lại, entropy (upload paths), SSDeep=%s, gray zone 25–%s%s"
            % (
                "on" if self.effective_policy.get("ssdeep_enabled_effective", True) else "off",
                self.effective_policy.get("min_score_effective", 40) - 1,
                vt_note,
            ),
        )
        self.preflight_results = run_preflight_checks(self, logger)
        log_preflight_summary(logger, self.preflight_results)
        self._apply_preflight_fixes()

    def _apply_preflight_fixes(self):
        """Disable broken optional modules; abort if YARA unusable."""
        for check in self.preflight_results:
            if check["status"] != STATUS_ERROR:
                continue
            comp = check["component"]
            if comp == "YARA":
                logger.log("ERROR", "Health", "Cannot scan without YARA — exiting.")
                sys.exit(1)
            if comp == "deobfuscate":
                self.effective_policy["deobfuscate_enabled"] = False
                logger.log("WARNING", "Health", "Deobfuscate disabled for this run due to preflight failure.")
            if comp == "VT":
                self.effective_policy["vt_ssdeep_enabled"] = False
                logger.log("WARNING", "Health", "VT→SSDeep feed disabled for this run.")
            if comp == "entropy":
                self.effective_policy["entropy_enabled_effective"] = False
                logger.log("WARNING", "Health", "Entropy heuristic disabled for this run due to preflight failure.")

    def _get_min_score(self, args):
        if args and getattr(args, "min_score", None) is not None:
            return int(args.min_score)
        return int(self.effective_policy.get("min_score_effective", 40))

    def _get_gray_zone_min(self):
        return int(self.effective_policy.get("gray_zone_min_score", 25))

    def _append_gray_zone_row(self, file_path, sha256, score, time_str, description, extension,
                              is_multiprocessing=False, result_dict=None):
        row = {
            'file': file_path,
            'sha256': sha256 or "N/A",
            'score': score,
            'time': time_str,
            'description': description,
            'extension': extension,
            'virustotal': virustotal_file_url(sha256),
        }
        if is_multiprocessing and result_dict is not None:
            result_dict.setdefault('gray_zone', []).append(row)
            return
        with self.result_lock:
            gray_zone_csv["FILE"].append(file_path)
            gray_zone_csv["SHA256"].append(sha256 or "N/A")
            gray_zone_csv["SCORE"].append(score)
            gray_zone_csv["TIME"].append(time_str)
            gray_zone_csv["DESCRIPTION"].append(description)
            gray_zone_csv["EXTENSION"].append(extension)
            gray_zone_csv["VIRUSTOTAL_URL"].append(virustotal_file_url(sha256))
            gray_zone_csv["VT_CHECKED"].append("")
            gray_zone_csv["VT_RESULT"].append("")

    def get_ssdeep_db_path(self):
        return ssdeep_db.get_ssdeep_db_path(self.app_path)

    def reload_ssdeep_signatures(self):
        ssdeep_file = self.get_ssdeep_db_path()
        self.ssdeep_signatures = []
        self.ssdeep_index = {}
        if os.path.exists(ssdeep_file):
            self.initialize_ssdeep_signatures(ssdeep_file)
        return len(self.ssdeep_signatures)

    def collect_vt_ssdeep_candidates(self):
        """Gom FILE+SHA256 từ findings và gray zone (dedupe theo SHA256)."""
        policy = self.effective_policy
        include_findings = bool(policy.get("vt_include_findings", True))
        include_gray = bool(policy.get("vt_include_gray_zone", True))
        seen = {}
        sha_re = re.compile(r"^[a-fA-F0-9]{64}$")

        def add_row(file_path, sha256, score):
            sha = (sha256 or "").strip().lower()
            if not sha_re.match(sha):
                return
            if int(sha, 16) in self.false_hashes:
                return
            if sha not in seen:
                seen[sha] = {"file": file_path, "sha256": sha, "score": score}

        if include_findings:
            files = fileInfo_csv.get("FILE", [])
            shas = fileInfo_csv.get("SHA256", [])
            scores = fileInfo_csv.get("SCORE", [])
            for i, sha in enumerate(shas):
                fp = files[i] if i < len(files) else ""
                sc = scores[i] if i < len(scores) else None
                add_row(fp, sha, sc)
        if include_gray:
            files = gray_zone_csv.get("FILE", [])
            shas = gray_zone_csv.get("SHA256", [])
            scores = gray_zone_csv.get("SCORE", [])
            for i, sha in enumerate(shas):
                fp = files[i] if i < len(files) else ""
                sc = scores[i] if i < len(scores) else None
                add_row(fp, sha, sc)
        return list(seen.values())

    def _update_gray_zone_vt_columns(self, sha256, checked, vt_result):
        sha = (sha256 or "").strip().lower()
        shas = gray_zone_csv.get("SHA256", [])
        for i, val in enumerate(shas):
            if str(val).strip().lower() == sha:
                if i < len(gray_zone_csv.get("VT_CHECKED", [])):
                    gray_zone_csv["VT_CHECKED"][i] = checked
                if i < len(gray_zone_csv.get("VT_RESULT", [])):
                    gray_zone_csv["VT_RESULT"][i] = vt_result

    def run_vt_ssdeep_feed(self, args=None):
        """
        Mở VirusTotal trên trình duyệt (không API); nếu bạn xác nhận mã độc thì thêm SSDeep.
        """
        policy = self.effective_policy
        if not policy.get("vt_ssdeep_enabled"):
            return {"checked": 0, "malicious": 0, "ssdeep_added": 0}

        candidates = self.collect_vt_ssdeep_candidates()
        if not candidates:
            logger.log("INFO", "VT", "Không có SHA256 để tra VirusTotal.")
            return {"checked": 0, "malicious": 0, "ssdeep_added": 0}

        max_bytes = int(policy.get("vt_max_file_bytes", 5 * 1024 * 1024))
        ssdeep_file = self.get_ssdeep_db_path()
        total = len(candidates)

        logger.log(
            "NOTICE", "VT",
            "Tra VT qua trình duyệt cho %s hash — nhập [m] nếu trang VT báo mã độc (vd. 15/72)"
            % total,
        )
        print("\n*** VirusTotal (trình duyệt) — không dùng API ***")
        print("Mỗi hash: xem detections/total trên web → m=malicious, c=clean, s=skip, q=thoát\n")

        checked = malicious = added = 0
        for idx, item in enumerate(candidates, start=1):
            sha = item["sha256"]
            file_path = item["file"]
            score = item.get("score")

            result = prompt_browser_verdict(
                sha, file_path, score=score, open_browser=True, index=idx, total=total,
            )
            verdict = result["verdict"]
            vt_result = result.get("vt_result") or ""

            if verdict == "quit":
                logger.log("NOTICE", "VT", "Dừng tra VT theo yêu cầu người dùng.")
                break

            if verdict == "skip":
                self._update_gray_zone_vt_columns(sha, "skip", vt_result)
                continue

            checked += 1
            self._update_gray_zone_vt_columns(sha, "yes", vt_result)

            if verdict != "malicious":
                continue

            malicious += 1
            vt_label = result.get("vt_ratio") or "manual"

            if not os.path.isfile(file_path):
                logger.log("WARNING", "VT", "VT mã độc (%s) nhưng không đọc được file: %s" % (vt_result, file_path))
                continue

            ok, msg = ssdeep_db.append_from_file(
                file_path, ssdeep_file, source=vt_label, max_bytes=max_bytes,
            )
            if ok:
                added += 1
                logger.log(
                    "NOTICE", "VT",
                    "VT %s → đã thêm SSDeep: %s (%s)" % (vt_result, os.path.basename(file_path), msg),
                )
            else:
                logger.log("DEBUG", "VT", "VT mã độc nhưng SSDeep: %s — %s" % (vt_result, msg))

        if added:
            n = self.reload_ssdeep_signatures()
            logger.log("INFO", "VT", "Đã nạp lại %s chữ ký SSDeep sau khi thêm %s mẫu từ VT" % (n, added))

        logger.log(
            "NOTICE", "VT",
            "VT (trình duyệt) xong: đã tra %s, mã độc %s, thêm SSDeep %s"
            % (checked, malicious, added),
        )
        return {"checked": checked, "malicious": malicious, "ssdeep_added": added}

    def _iter_yara_scan_targets(self, file_data, extension, file_path):
        if should_deobfuscate(extension, file_path, self.effective_policy):
            for layer_name, layer_data in iter_deobfuscated_layers(file_data, self.effective_policy):
                yield (layer_name, layer_data)
        else:
            yield ("raw", file_data)

    def _collect_yara_matches(self, file_data, file_type, file_name, file_path, extension, md5, timeout=20.0):
        """Run YARA on raw + deobfuscated layers; return list of (layer, score, rule, ...)."""
        collected = []
        try:
            for layer_name, layer_data in self._iter_yara_scan_targets(file_data, extension, file_path):
                for match_tuple in self.scan_data(
                        fileData=layer_data,
                        fileType=file_type,
                        fileName=file_name,
                        filePath=file_path,
                        extension=extension,
                        md5=md5,
                        timeout=timeout):
                    collected.append((layer_name,) + match_tuple)
        except yara.TimeoutError:
            return None, True
        return collected, False

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
    def _add_group_score(group_scores, group, score, cap=None):
        try:
            score = int(score)
        except Exception:
            return 0
        if score <= 0:
            return 0
        current = int(group_scores.get(group, 0))
        limit = int(cap) if cap is not None else current + score
        new_total = min(limit, current + score)
        delta = max(0, new_total - current)
        group_scores[group] = new_total
        return delta

    @staticmethod
    def _confidence_summary(total_score, evidence_groups, yara_timeout=False):
        groups = sorted(evidence_groups)
        notes = []
        if not groups:
            notes.append("no_positive_evidence")
        if groups == ["entropy"]:
            notes.append("entropy_only")
        if groups == ["filename_ioc"]:
            notes.append("filename_only")
        if groups == ["yara"]:
            notes.append("single_yara_evidence_group")
        if "ssdeep" in groups and len(groups) == 1:
            notes.append("fuzzy_hash_only")
        if yara_timeout:
            notes.append("manual_review_yara_timeout")

        if "hash_ioc" in groups:
            confidence = "High"
        elif total_score >= 100 and len(groups) >= 2:
            confidence = "High"
        elif total_score >= 60 or len(groups) >= 2 or yara_timeout:
            confidence = "Medium"
        else:
            confidence = "Low"

        return "CONFIDENCE: %s EVIDENCE_GROUPS: %s FP_NOTES: %s" % (
            confidence,
            ",".join(groups) if groups else "-",
            ",".join(notes) if notes else "-",
        )

    def _single_evidence_gray_reason(self, total_score, evidence_groups):
        if not self.effective_policy.get("single_evidence_gray_enabled", True):
            return None
        groups = set(evidence_groups or [])
        if groups == {"webshell_capability"}:
            threshold = int(self.effective_policy.get("single_webshell_capability_main_min_score", 80))
            if total_score < threshold:
                return "single_webshell_capability_below_main_threshold=%s" % threshold
        if groups == {"behavior_graph"}:
            threshold = int(self.effective_policy.get("single_behavior_graph_main_min_score", 85))
            if total_score < threshold:
                return "single_behavior_graph_below_main_threshold=%s" % threshold
        return None

    @staticmethod
    def _ssdeep_blocksize(digest):
        try:
            return int(str(digest).split(":", 1)[0])
        except Exception:
            return None

    def _index_ssdeep_signature(self, digest, filename):
        self.ssdeep_signatures.append((digest, filename))
        block = self._ssdeep_blocksize(digest)
        if block:
            self.ssdeep_index.setdefault(block, []).append((digest, filename))

    def _iter_ssdeep_candidates(self, digest):
        block = self._ssdeep_blocksize(digest)
        if not block or not self.ssdeep_index:
            return self.ssdeep_signatures
        candidate_blocks = {block}
        if block > 1:
            candidate_blocks.add(block // 2)
        candidate_blocks.add(block * 2)
        candidates = []
        seen = set()
        for candidate_block in candidate_blocks:
            for item in self.ssdeep_index.get(candidate_block, []):
                if item[0] not in seen:
                    seen.add(item[0])
                    candidates.append(item)
        return candidates or self.ssdeep_signatures

    def _best_ssdeep_match(self, file_ssdeep_hash):
        best_match_score = 0
        best_match_hash = None
        best_match_filename = None
        comparisons_count = 0
        for known_hash, known_filename in self._iter_ssdeep_candidates(file_ssdeep_hash):
            try:
                similarity = ssdeep.compare(file_ssdeep_hash, known_hash)
                comparisons_count += 1
                if similarity > best_match_score:
                    best_match_score = similarity
                    best_match_hash = known_hash
                    best_match_filename = known_filename
            except Exception as e:
                logger.log("DEBUG", "SSDeep", f"Error comparing hash: {str(e)}")
                continue
        return best_match_score, best_match_hash, best_match_filename, comparisons_count

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
        return self.archive_extractor.is_archive_file(filePath)

    def _archive_member_destination(self, archive_temp_dir, member_name):
        return self.archive_extractor.member_destination(archive_temp_dir, member_name)

    def _check_archive_budget(self, state, member_size, archive_path):
        return self.archive_extractor.check_budget(state, member_size, archive_path)

    def _copy_stream_limited(self, src, dst, state, archive_path):
        return self.archive_extractor.copy_stream_limited(src, dst, state, archive_path)

    def _collect_extracted_files_with_budget(self, archive_temp_dir, archive_path):
        return self.archive_extractor.collect_extracted_files_with_budget(archive_temp_dir, archive_path)

    def extract_archive(self, archive_path, temp_dir):
        """Extract archive to temporary directory. Returns list of extracted file paths."""
        return self.archive_extractor.extract(archive_path, temp_dir)

    def scan_archive_recursive(self, archive_path, temp_dir, parent_archive="", args=None, _depth=0):
        """Scan archive and recursively scan nested archives. Returns list of findings.
        
        _depth: current recursion depth — protected against zip bomb via MAX_ARCHIVE_DEPTH.
        """
        findings = []  # List of (file_path, score, reasons, archive_path)

        # Zip bomb / deeply nested archive protection
        if _depth >= self.MAX_ARCHIVE_DEPTH:
            logger.log("WARNING", "Archive",
                       f"Max archive nesting depth ({self.MAX_ARCHIVE_DEPTH}) reached, "
                       f"skipping: {archive_path}")
            return findings

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
                                # Recursively scan nested archive (pass incremented depth)
                                nested_parent = f"{parent_archive} -> {os.path.basename(archive_path)}" if parent_archive else os.path.basename(archive_path)
                                nested_findings = self.scan_archive_recursive(
                                    extracted_file, temp_dir, nested_parent, args, _depth=_depth + 1)
                                findings.extend(nested_findings)
                            else:
                                logger.log("DEBUG", "Archive", f"Skipping nested archive {extracted_file} (size {nested_size} > {self.MAX_ARCHIVE_SIZE})")
                        except Exception as e:
                            logger.log("WARNING", "Archive", f"Cannot get size of nested archive {extracted_file}: {str(e)}")
                    
                    # Scan the file (whether it's an archive or not)
                    file_reasons = []
                    file_score = 0
                    file_group_scores = {}
                    file_evidence_groups = set()
                    self.scan_stats.inc("archive_files_scanned", 1)

                    if self._is_git_metadata_file(extracted_file):
                        continue

                    if self._is_benign_non_webshell_file(extracted_file):
                        continue

                    # Read file data
                    file_data = self.get_file_data(extracted_file)
                    if not file_data:
                        continue

                    if self._is_icu_data_file(extracted_file, file_data):
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
                        delta = self._add_group_score(file_group_scores, "hash_ioc", 100, cap=100)
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("hash_ioc")
                    if self.ioc_contains(self.hashes_sha1_list, sha1_num):
                        file_reasons.append(f"Malware Hash TYPE: SHA1 HASH: {sha1} SUBSCORE: 100 DESC: {self.hashes_sha1[sha1_num]}")
                        delta = self._add_group_score(file_group_scores, "hash_ioc", 100, cap=100)
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("hash_ioc")
                    if self.ioc_contains(self.hashes_sha256_list, sha256_num):
                        file_reasons.append(f"Malware Hash TYPE: SHA256 HASH: {sha256} SUBSCORE: 100 DESC: {self.hashes_sha256[sha256_num]}")
                        delta = self._add_group_score(file_group_scores, "hash_ioc", 100, cap=100)
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("hash_ioc")
                    
                    # SSDeep check
                    if (self.effective_policy.get("ssdeep_enabled_effective", True)
                            and ssdeep is not None and self.ssdeep_signatures and file_data):
                        try:
                            ssdeep_inputs = [("raw", file_data)]
                            normalized_data = ssdeep_db.normalize_source_for_similarity(file_data, os.path.splitext(extracted_file)[1].lower())
                            if normalized_data and normalized_data != file_data:
                                ssdeep_inputs.append(("normalized", normalized_data))
                            best_match_score = 0
                            best_match_hash = None
                            best_match_filename = None
                            best_match_layer = "raw"
                            for ssdeep_layer, ssdeep_data in ssdeep_inputs:
                                file_ssdeep_hash = ssdeep.hash(ssdeep_data)
                                if not file_ssdeep_hash:
                                    continue
                                score, match_hash, match_filename, _comparisons = self._best_ssdeep_match(file_ssdeep_hash)
                                if score > best_match_score:
                                    best_match_score = score
                                    best_match_hash = match_hash
                                    best_match_filename = match_filename
                                    best_match_layer = ssdeep_layer

                            ssdeep_min = getattr(self, 'ssdeep_threshold', 50)
                            if best_match_score >= ssdeep_min:
                                delta = self._add_group_score(
                                    file_group_scores, "ssdeep", best_match_score,
                                    cap=int(self.effective_policy.get("ssdeep_score_cap", 100)))
                                file_reasons.append(
                                    f"SSDeep Match LAYER: {best_match_layer} SCORE: {best_match_score}% HASH: {best_match_hash} SUBSCORE: {delta} DESC: Similar to known webshell: {best_match_filename}")
                                if delta:
                                    file_score += delta
                                    file_evidence_groups.add("ssdeep")
                        except Exception:
                            pass
                    
                    extension = os.path.splitext(extracted_file)[1].lower()
                    fileType = get_file_type(extracted_file, self.filetype_magics, self.max_filetype_magics, logger)
                    filename_str = os.path.basename(extracted_file)
                    filepath_str = extracted_file

                    ent_score, ent_reason = entropy_heuristic(
                        file_data, extension, extracted_file, self.effective_policy,
                        paranoid=bool(self.effective_policy.get("paranoid_mode")),
                    )
                    if ent_score > 0 and ent_reason:
                        file_reasons.append(ent_reason)
                        delta = self._add_group_score(
                            file_group_scores, "entropy", ent_score,
                            cap=int(self.effective_policy.get("entropy_score_cap", ent_score)))
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("entropy")

                    ss_score, ss_reason = source_sink_heuristic(
                        file_data, extension, extracted_file, self.effective_policy,
                        paranoid=bool(self.effective_policy.get("paranoid_mode")),
                    )
                    if ss_score > 0 and ss_reason:
                        file_reasons.append(ss_reason)
                        delta = self._add_group_score(
                            file_group_scores, "source_sink", ss_score,
                            cap=int(self.effective_policy.get("source_sink_score_cap", ss_score)))
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("source_sink")

                    graph_score, graph_reason = behavior_graph_heuristic(
                        file_data, extension, extracted_file, self.effective_policy,
                        paranoid=bool(self.effective_policy.get("paranoid_mode")),
                    )
                    if graph_score > 0 and graph_reason:
                        file_reasons.append(graph_reason)
                        delta = self._add_group_score(
                            file_group_scores, "behavior_graph", graph_score,
                            cap=int(self.effective_policy.get("behavior_graph_score_cap", graph_score)))
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("behavior_graph")
                        self.scan_stats.inc("behavior_graph_hits", 1)

                    cap_score, cap_reason = webshell_capability_heuristic(
                        file_data, extension, extracted_file, self.effective_policy,
                        paranoid=bool(self.effective_policy.get("paranoid_mode")),
                    )
                    if cap_score > 0 and cap_reason:
                        file_reasons.append(cap_reason)
                        delta = self._add_group_score(
                            file_group_scores, "webshell_capability", cap_score,
                            cap=int(self.effective_policy.get("webshell_capability_score_cap", cap_score)))
                        if delta:
                            file_score += delta
                            file_evidence_groups.add("webshell_capability")

                    try:
                        yara_matches, _timed_out = self._collect_yara_matches(
                            file_data, fileType,
                            filename_str,
                            filepath_str,
                            extension, md5, timeout=20.0,
                        )
                        if yara_matches:
                            yara_cap = int(self.effective_policy.get("yara_score_cap", 120))
                            for (layer_name, score, rule, description, reference, matched_strings, author) in yara_matches:
                                prefix = ""
                                if layer_name and layer_name != "raw":
                                    prefix = "Deobfuscated[%s]: " % layer_name
                                delta = self._add_group_score(file_group_scores, "yara", score, cap=yara_cap)
                                message = "%sYara Rule MATCH: %s SUBSCORE: %s EFFECTIVE_SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s" % (
                                    prefix, rule, score, delta, description, reference, author)
                                if matched_strings:
                                    message += " MATCHES: %s" % matched_strings
                                file_reasons.append(message)
                                if delta:
                                    file_score += delta
                                    file_evidence_groups.add("yara")
                                if layer_name == "raw" or not layer_name:
                                    self.scan_stats.inc("yara_matches_raw", 1)
                                else:
                                    self.scan_stats.inc("yara_matches_deobfuscated", 1)
                    except Exception as exc:
                        logger.log("WARNING", "Archive",
                                   "YARA/deobfuscate scan failed for %s: %s" % (extracted_file, exc))
                        self.scan_stats.inc("files_errors", 1)
                    
                    fp_gate_reason = library_fp_gate(
                        extracted_file, extension, file_data, file_evidence_groups, file_reasons,
                        self.effective_policy)
                    if fp_gate_reason:
                        file_reasons.append("FP_GATE: %s" % fp_gate_reason)
                        logger.log("NOTICE", "Archive",
                                   "Library FP gate: %s (score %s, %s)"
                                   % (extracted_file, file_score, fp_gate_reason))
                        continue

                    if file_reasons:
                        file_reasons.append(self._confidence_summary(file_score, file_evidence_groups))

                    # If file has findings above report threshold, add to results
                    if file_score >= self._get_min_score(args) and not self._single_evidence_gray_reason(
                        file_score, file_evidence_groups
                    ):
                        archive_info = f" (in archive: {parent_archive} -> {os.path.basename(archive_path)})" if parent_archive else f" (in archive: {os.path.basename(archive_path)})"
                        findings.append((extracted_file + archive_info, file_score, file_reasons, archive_path, sha256))
                        
                except Exception as e:
                    logger.log("WARNING", "Archive", f"Error scanning extracted file {extracted_file}: {str(e)}")
                    continue
            
            return findings
            
        except Exception as e:
            logger.log("ERROR", "Archive", f"Error in scan_archive_recursive for {archive_path}: {str(e)}")
            return findings

    def _increment_progress(self, filePath, file_size, total):
        """Thread-safe progress increment and console output."""
        local_logger = logger if 'logger' in globals() else None
        if self.use_multiprocessing:
            with self.mp_progress_counter.get_lock():
                self.mp_progress_counter.value += 1
                current = self.mp_progress_counter.value
        else:
            with self.progress_lock:
                self.processed_files += 1
                current = self.processed_files

        from libs.logger import console_lock
        with console_lock():
            print_progress(current, total, local_logger)
            if not getattr(self, 'parallel_console', False):
                try:
                    print(f"{filePath}\t Size: {file_size / 1024 / 1024} MB")
                except Exception:
                    pass

    def _is_git_metadata_file(self, file_path):
        return self.benign_filter.is_metadata_file(file_path)

    def _is_benign_non_webshell_file(self, file_path):
        return self.benign_filter.is_non_webshell_file(file_path)

    def _is_icu_data_file(self, file_path, file_data):
        return self.benign_filter.is_icu_data_file(file_path, file_data)

    @staticmethod
    def _is_inside_path(path, parent):
        try:
            return os.path.commonpath([os.path.realpath(path), os.path.realpath(parent)]) == os.path.realpath(parent)
        except ValueError:
            return False

    def _is_scanner_internal_path(self, path):
        internal_dirs = [
            os.path.join(self.app_path, "logs"),
            os.path.join(self.app_path, "quarantine"),
            os.path.join(self.app_path, "libs", "signature-base"),
        ]
        return any(self._is_inside_path(path, internal_dir) for internal_dir in internal_dirs)

    def _append_finding_csv_row(self, file_path, sha256, score, time_str, description, extension):
        """Ghi một dòng vào báo cáo file nghi ngờ (fileInfo_csv)."""
        with self.result_lock:
            fileInfo_csv["FILE"].append(file_path)
            fileInfo_csv["SHA256"].append(sha256 or "N/A")
            fileInfo_csv["SCORE"].append(score)
            fileInfo_csv["TIME"].append(time_str)
            fileInfo_csv["DESCRIPTION"].append(description)
            fileInfo_csv["EXTENSION"].append(extension)

    def _build_exact_quarantine_path(self, quarantine_dir, src, sha256):
        """
        Build a quarantine destination that keeps the original filename unless
        the same name already exists with different content.
        """
        return self.quarantine_manager.build_exact_path(quarantine_dir, src, sha256)

    def _record_all_file(self, all_file_info, sha256='N/A',
                          is_multiprocessing=False, result_dict=None, recorded_flag=None):
        """Ghi file đã quét (kèm SHA256) vào all_files_csv / result_dict — mỗi file chỉ ghi một lần."""
        if recorded_flag is not None and recorded_flag[0]:
            return
        all_file_info['SHA256'] = sha256
        if is_multiprocessing and result_dict is not None:
            result_dict['all_file_info'] = all_file_info
        else:
            with self.result_lock:
                all_files_csv["FILE"].append(all_file_info['FILE'])
                all_files_csv["SHA256"].append(sha256)
                all_files_csv["TIME_CREATED"].append(all_file_info['TIME_CREATED'])
                all_files_csv["TIME_MODIFIED"].append(all_file_info['TIME_MODIFIED'])
                all_files_csv["TIME_ACCESSED"].append(all_file_info['TIME_ACCESSED'])
                all_files_csv["EXTENSION"].append(all_file_info['EXTENSION'])
        if recorded_flag is not None:
            recorded_flag[0] = True

    def _worker_process_file(self, file_queue, args, app_path_lower, total, result_queue=None, progress_counter=None):
        """Worker process/thread to process files from queue."""
        is_multiprocessing = result_queue is not None
        try:
            if is_multiprocessing:
                process_name = multiprocessing.current_process().name
                process_id = multiprocessing.current_process().pid
            else:
                process_name = threading.current_thread().name
                process_id = threading.current_thread().ident
        except:
            process_name = "Unknown"
            process_id = 0
            
        worker_tag = "%s-%s" % (process_name, process_id)

        from libs.logger import set_log_worker_tag, clear_log_worker_tag
        set_log_worker_tag(worker_tag)

        if 'logger' in globals():
            logger.parallel_mode = True
            worker_type = "process" if is_multiprocessing else "thread"
            logger.log("INFO", "FileScan", f"Worker {worker_type} {process_name} (ID: {process_id}) started and waiting for files")

        try:
            self._worker_loop(
                file_queue, args, app_path_lower, total, result_queue,
                is_multiprocessing, process_name, process_id, progress_counter,
            )
        finally:
            clear_log_worker_tag()

    def _worker_loop(self, file_queue, args, app_path_lower, total, result_queue,
                     is_multiprocessing, process_name, process_id, progress_counter=None):
        files_processed = 0
        while True:
            try:
                file_path = file_queue.get()
            except Exception as e:
                if 'logger' in globals():
                    logger.log("ERROR", "FileScan", f"Error getting file from queue: {str(e)}")
                break
                
            if file_path is None:
                # Shutdown signal received
                if not is_multiprocessing:
                    try:
                        file_queue.task_done()
                    except:
                        pass
                if 'logger' in globals():
                    worker_type = "process" if is_multiprocessing else "thread"
                    logger.log("INFO", "FileScan", f"Worker {worker_type} {process_name} (ID: {process_id}) received shutdown signal. Processed {files_processed} file(s)")
                break
            
            try:
                if 'logger' in globals():
                    logger.log("DEBUG", "FileScan", f"Worker {process_name} (ID: {process_id}) processing file: {file_path}")
                
                # Process file and get results
                result = self.process_single_file_with_result(file_path, args, app_path_lower, total, is_multiprocessing, progress_counter)
                
                # Send result back to main process if using multiprocessing
                if is_multiprocessing and result:
                    try:
                        result_queue.put(result)
                    except Exception as e:
                        if 'logger' in globals():
                            logger.log("ERROR", "FileScan", f"Error putting result to queue: {str(e)}")
                
                files_processed += 1
            except Exception as e:
                if 'logger' in globals():
                    logger.log("ERROR", "FileScan", f"Unhandled error scanning file {file_path}: {str(e)}")
                traceback.print_exc()
            finally:
                if not is_multiprocessing:
                    try:
                        file_queue.task_done()
                    except:
                        pass
        
        if 'logger' in globals():
            worker_type = "process" if is_multiprocessing else "thread"
            logger.log("INFO", "FileScan", f"Worker {worker_type} {process_name} (ID: {process_id}) finished. Total files processed: {files_processed}")

    def process_single_file_with_result(self, filePath, args, app_path_lower, total, is_multiprocessing=False, progress_counter=None):
        """Process a single file and return result dict for multiprocessing, or None for threading mode."""
        result = {
            'all_file_info': None,
            'findings': [],
            'gray_zone': [],
        }
        
        try:
            # Call the original function but capture results
            self._process_single_file_internal(filePath, args, app_path_lower, total, is_multiprocessing, progress_counter, result)
        except Exception as e:
            logger.log("ERROR", "FileScan", f"Error processing file {filePath}: {str(e)}")
            traceback.print_exc()
        
        return result if (result['all_file_info'] or result['findings']) else None

    def process_single_file(self, filePath, args, app_path_lower, total):
        """Process a single file path (hashing, YARA, etc.) - threading mode."""
        self._process_single_file_internal(filePath, args, app_path_lower, total, False, None, None)

    def _process_single_file_internal(self, filePath, args, app_path_lower, total, is_multiprocessing=False, progress_counter=None, result_dict=None):
        """Internal function to process a single file path (hashing, YARA, etc.)."""
        local_stats = {}
        try:
            reasons = []
            total_score = 0
            group_scores = {}
            evidence_groups = set()
            yara_timeout_occurred = False
            all_file_recorded = [False]

            fpath = os.path.split(filePath)[0]
            # Keep as str — scan_data/YARA externals expect str, not bytes.
            # Use full path (filePath) for filepath, basename for filename.
            filePathCleaned = filePath.encode('ascii', errors='replace').decode('ascii')
            filename = os.path.basename(filePath)
            fileNameCleaned = filename.encode('ascii', errors='replace').decode('ascii')
            extension = os.path.splitext(filePath)[1].lower()

            skipIt = False

            try:
                file_stat = os.stat(filePath)
                file_size = file_stat.st_size
            except (OSError, IOError) as e:
                logger.log("DEBUG", "FileScan", f"Cannot stat file {filePath}: {str(e)}")
                return

            # Exclude check BEFORE logging/all_files_csv to avoid oversized logs
            for skip in self.fullExcludes:
                if skip.search(filePath):
                    skipIt = True
                    break

            if os_platform == "linux":
                for skip in self.LINUX_PATH_SKIPS_END:
                    if filePath.endswith(skip):
                        skipIt = True
                        break

                mode = file_stat.st_mode
                if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(mode) or stat.S_ISSOCK(mode):
                    return

            if skipIt:
                return

            local_stats["files_processed"] = local_stats.get("files_processed", 0) + 1

            try:
                created_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_stat.st_ctime))
                modified_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_stat.st_mtime))
                accessed_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file_stat.st_atime))
            except Exception:
                created_time = "not_available"
                modified_time = "not_available"
                accessed_time = "not_available"

            # Ghi nhận tất cả file ngay sau khi đọc stat (kể cả file bị bỏ qua sau đó)
            all_file_info = {
                'FILE': filePath,
                'TIME_CREATED': created_time,
                'TIME_MODIFIED': modified_time,
                'TIME_ACCESSED': accessed_time,
                'EXTENSION': extension
            }

            is_archive, archive_ext = self.is_archive_file(filePath)
            if is_archive and file_size <= self.MAX_ARCHIVE_SIZE:
                temp_dir = tempfile.mkdtemp(prefix='webshell_scan_archive_')
                try:
                    logger.log("INFO", "Archive", f"Scanning archive: {filePath} (size: {file_size} bytes)")
                    archive_findings = self.scan_archive_recursive(filePath, temp_dir, "", args)

                    if archive_findings:
                        for finding_file, finding_score, finding_reasons, original_archive, f_sha256 in archive_findings:
                            archive_path_info = f"\n ARCHIVE: {filePath}\n"
                            fileInfo = "===========================================================\n" \
                                       "FILE: %s%s SCORE: %s%s\n %s" % (
                                           finding_file, archive_path_info, finding_score, getAgeString(filePath),
                                           format_sha256_line(f_sha256))

                            message_type = "INFO"
                            if finding_score >= 100:
                                message_type = "ALERT"
                            elif finding_score >= 60:
                                message_type = "WARNING"
                            elif finding_score >= 40:
                                message_type = "NOTICE"

                            reason_lines = []
                            reason_csv_lines = []
                            for i, r in enumerate(finding_reasons):
                                reason_lines.append("\tREASON_{0}: {1}\n ".format(i + 1, r))
                                reason_csv_lines.append("REASON_{0}: {1}\n ".format(i + 1, r))

                            message_body = fileInfo + "".join(reason_lines)
                            message_csv = "".join(reason_csv_lines)

                            finding_data = {
                                'score': finding_score,
                                'message_type': message_type,
                                'message_body': message_body,
                                'file': f"{finding_file} [ARCHIVE: {filePath}]",
                                'time': getAgeString(filePath),
                                'description': message_csv,
                                'extension': extension,
                                'sha256': f_sha256
                            }
                            
                            if is_multiprocessing and result_dict:
                                result_dict['findings'].append(finding_data)
                            else:
                                with self.result_lock:
                                    MESSAGE.append([finding_score, message_type, message_body])
                                self._append_finding_csv_row(
                                    f"{finding_file} [ARCHIVE: {filePath}]",
                                    f_sha256, finding_score, getAgeString(filePath), message_csv, extension)

                            logger.log("INFO", "Archive", f"Found webshell in archive: {finding_file} (score: {finding_score}) in archive: {filePath}")

                except Exception as e:
                    logger.log("ERROR", "Archive", f"Error processing archive {filePath}: {str(e)}")
                finally:
                    try:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        logger.log("DEBUG", "Archive", f"Cleaned up temporary directory: {temp_dir}")
                    except Exception as e:
                        logger.log("WARNING", "Archive", f"Cannot cleanup temporary directory {temp_dir}: {str(e)}")

                self._record_all_file(all_file_info, is_multiprocessing=is_multiprocessing,
                                      result_dict=result_dict, recorded_flag=all_file_recorded)
                return

            # Note: exclude check already done above before archive branch — no need to repeat here.
            # skipIt is still valid from the first check.
            if os_platform == "linux":
                mode = file_stat.st_mode
                if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(mode) or stat.S_ISSOCK(mode):
                    self._record_all_file(all_file_info, is_multiprocessing=is_multiprocessing,
                                          result_dict=result_dict, recorded_flag=all_file_recorded)
                    return

            if skipIt:
                self._record_all_file(all_file_info, is_multiprocessing=is_multiprocessing,
                                      result_dict=result_dict, recorded_flag=all_file_recorded)
                return

            if is_multiprocessing and progress_counter:
                # Use multiprocessing counter
                with progress_counter.get_lock():
                    progress_counter.value += 1
                    current = progress_counter.value
                print_progress(current, total, logger if 'logger' in globals() else None)
                try:
                    print(f"{filePath}\t Size: {file_size / 1024 / 1024} MB")
                except Exception:
                    pass
            else:
                self._increment_progress(filePath, file_size, total)

            if self._is_scanner_internal_path(filePath):
                self._record_all_file(all_file_info, is_multiprocessing=is_multiprocessing,
                                      result_dict=result_dict, recorded_flag=all_file_recorded)
                return

            for fioc in self.filename_iocs:
                match = fioc['regex'].search(filePath)
                if match:
                    if fioc['regex_fp']:
                        match_fp = fioc['regex_fp'].search(filePath)
                        if match_fp:
                            continue
                    reasons.append("File Name IOC matched PATTERN: %s SUBSCORE: %s DESC: %s" % (
                        fioc['regex'].pattern, fioc['score'], fioc['description']))
                    delta = self._add_group_score(
                        group_scores, "filename_ioc", fioc['score'],
                        cap=int(self.effective_policy.get("filename_ioc_score_cap", 80)))
                    if delta:
                        total_score += delta
                        evidence_groups.add("filename_ioc")

            fileType = get_file_type(filePath, self.filetype_magics, self.max_filetype_magics, logger)

            fileData = self.get_file_data(filePath)

            matchType = None
            matchDesc = None
            matchHash = None
            md5 = "0"
            sha1 = "0"
            sha256 = "0"

            md5, sha1, sha256 = generateHashes(fileData)

            # If generateHashes returned sentinel "0" (file unreadable / error), skip scanning
            if md5 == "0" or sha1 == "0" or sha256 == "0":
                logger.log("DEBUG", "FileScan", f"Skipping unreadable file (hash error): {filePath}")
                self._record_all_file(all_file_info, sha256="N/A",
                                      is_multiprocessing=is_multiprocessing, result_dict=result_dict,
                                      recorded_flag=all_file_recorded)
                return

            md5_num = int(md5, 16)
            sha1_num = int(sha1, 16)
            sha256_num = int(sha256, 16)

            EMPTY_FILE_MD5 = int('d41d8cd98f00b204e9800998ecf8427e', 16)
            EMPTY_FILE_SHA1 = int('da39a3ee5e6b4b0d3255bfef95601890afd80709', 16)
            EMPTY_FILE_SHA256 = int('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 16)
            self._record_all_file(all_file_info, sha256=sha256,
                                  is_multiprocessing=is_multiprocessing, result_dict=result_dict,
                                  recorded_flag=all_file_recorded)

            if self._is_git_metadata_file(filePath):
                logger.log("DEBUG", "FileScan", f"Skipping benign Git metadata file: {filePath}")
                return

            if self._is_benign_non_webshell_file(filePath):
                logger.log("DEBUG", "FileScan", f"Skipping benign non-server-side webshell file: {filePath}")
                return

            if md5_num == EMPTY_FILE_MD5 or sha1_num == EMPTY_FILE_SHA1 or sha256_num == EMPTY_FILE_SHA256:
                logger.log("DEBUG", "FileScan", f"Skipping empty file: {filePath}")
                return

            if self._is_icu_data_file(filePath, fileData):
                logger.log("DEBUG", "FileScan", f"Skipping benign ICU data file: {filePath}")
                return

            if md5_num in self.false_hashes or sha1_num in self.false_hashes or sha256_num in self.false_hashes:
                return

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

            if matchType:
                reasons.append("Malware Hash TYPE: %s HASH: %s SUBSCORE: 100 DESC: %s" % (
                    matchType, matchHash, matchDesc))
                delta = self._add_group_score(group_scores, "hash_ioc", 100, cap=100)
                if delta:
                    total_score += delta
                    evidence_groups.add("hash_ioc")
                local_stats["hash_ioc_hits"] = local_stats.get("hash_ioc_hits", 0) + 1

            ent_score, ent_reason = entropy_heuristic(
                fileData, extension, filePath, self.effective_policy,
                paranoid=bool(self.effective_policy.get("paranoid_mode")),
            )
            if ent_score > 0 and ent_reason:
                reasons.append(ent_reason)
                delta = self._add_group_score(
                    group_scores, "entropy", ent_score,
                    cap=int(self.effective_policy.get("entropy_score_cap", ent_score)))
                if delta:
                    total_score += delta
                    evidence_groups.add("entropy")
                local_stats["entropy_hits"] = local_stats.get("entropy_hits", 0) + 1

            ss_score, ss_reason = source_sink_heuristic(
                fileData, extension, filePath, self.effective_policy,
                paranoid=bool(self.effective_policy.get("paranoid_mode")),
            )
            if ss_score > 0 and ss_reason:
                reasons.append(ss_reason)
                delta = self._add_group_score(
                    group_scores, "source_sink", ss_score,
                    cap=int(self.effective_policy.get("source_sink_score_cap", ss_score)))
                if delta:
                    total_score += delta
                    evidence_groups.add("source_sink")
                local_stats["source_sink_hits"] = local_stats.get("source_sink_hits", 0) + 1

            graph_score, graph_reason = behavior_graph_heuristic(
                fileData, extension, filePath, self.effective_policy,
                paranoid=bool(self.effective_policy.get("paranoid_mode")),
            )
            if graph_score > 0 and graph_reason:
                reasons.append(graph_reason)
                delta = self._add_group_score(
                    group_scores, "behavior_graph", graph_score,
                    cap=int(self.effective_policy.get("behavior_graph_score_cap", graph_score)))
                if delta:
                    total_score += delta
                    evidence_groups.add("behavior_graph")
                local_stats["behavior_graph_hits"] = local_stats.get("behavior_graph_hits", 0) + 1

            cap_score, cap_reason = webshell_capability_heuristic(
                fileData, extension, filePath, self.effective_policy,
                paranoid=bool(self.effective_policy.get("paranoid_mode")),
            )
            if cap_score > 0 and cap_reason:
                reasons.append(cap_reason)
                delta = self._add_group_score(
                    group_scores, "webshell_capability", cap_score,
                    cap=int(self.effective_policy.get("webshell_capability_score_cap", cap_score)))
                if delta:
                    total_score += delta
                    evidence_groups.add("webshell_capability")
                local_stats["webshell_capability_hits"] = local_stats.get("webshell_capability_hits", 0) + 1

            if (self.effective_policy.get("ssdeep_enabled_effective", True)
                    and ssdeep is not None and self.ssdeep_signatures and fileData):
                try:
                    logger.log("DEBUG", "SSDeep", f"Checking file with SSDeep: {filePath}")
                    ssdeep_inputs = [("raw", fileData)]
                    normalized_data = ssdeep_db.normalize_source_for_similarity(fileData, extension)
                    if normalized_data and normalized_data != fileData:
                        ssdeep_inputs.append(("normalized", normalized_data))

                    best_match_score = 0
                    best_match_hash = None
                    best_match_filename = None
                    best_match_layer = "raw"
                    comparisons_count = 0
                    for ssdeep_layer, ssdeep_data in ssdeep_inputs:
                        file_ssdeep_hash = ssdeep.hash(ssdeep_data)
                        logger.log("DEBUG", "SSDeep", f"Generated SSDeep hash ({ssdeep_layer}): {file_ssdeep_hash}")
                        if not file_ssdeep_hash:
                            continue
                        score, match_hash, match_filename, comparisons = self._best_ssdeep_match(file_ssdeep_hash)
                        comparisons_count += comparisons
                        if score > best_match_score:
                            best_match_score = score
                            best_match_hash = match_hash
                            best_match_filename = match_filename
                            best_match_layer = ssdeep_layer

                    logger.log("DEBUG", "SSDeep", f"Compared with {comparisons_count} indexed signatures, best match: {best_match_score}%")

                    ssdeep_min = getattr(self, 'ssdeep_threshold', 50)
                    if best_match_score >= ssdeep_min:
                        logger.log("DEBUG", "SSDeep", f"SSDeep match found: {best_match_score}% similarity with {best_match_filename}")
                        delta = self._add_group_score(
                            group_scores, "ssdeep", best_match_score,
                            cap=int(self.effective_policy.get("ssdeep_score_cap", 100)))
                        reason_text = "SSDeep Match LAYER: %s SCORE: %d%% HASH: %s SUBSCORE: %s DESC: Similar to known webshell: %s" % (
                            best_match_layer, best_match_score, best_match_hash, delta, best_match_filename)
                        reasons.append(reason_text)
                        if delta:
                            total_score += delta
                            evidence_groups.add("ssdeep")
                        local_stats["ssdeep_hits"] = local_stats.get("ssdeep_hits", 0) + 1
                        logger.log("DEBUG", "SSDeep", f"Added SSDeep match to reasons. Total score now: {total_score}")
                    else:
                        logger.log("DEBUG", "SSDeep", f"No SSDeep match (best: {best_match_score}%, threshold: {ssdeep_min}%)")
                except Exception as e:
                    logger.log("WARNING", "SSDeep", f"SSDeep check failed for {filePath}: {str(e)}")

            YARA_SCAN_TIMEOUT = 20.0
            yara_scan_start_time = time.time()

            try:
                yara_matches, timed_out = self._collect_yara_matches(
                    fileData, fileType, fileNameCleaned, filePathCleaned, extension, md5,
                    timeout=YARA_SCAN_TIMEOUT,
                )
                if timed_out:
                    elapsed_time = time.time() - yara_scan_start_time
                    yara_timeout_occurred = True
                    timeout_message = (
                        "YARA SCAN TIMEOUT: YARA rule matching exceeded %ss (actual: %.2fs). "
                        "File requires manual review." % (YARA_SCAN_TIMEOUT, elapsed_time)
                    )
                    logger.log("WARNING", "FileScan",
                               "YARA scan timeout (%.2fs > %ss) for file: %s"
                               % (elapsed_time, YARA_SCAN_TIMEOUT, filePath))
                    reasons.append(timeout_message)
                    local_stats["yara_timeouts"] = local_stats.get("yara_timeouts", 0) + 1
                elif yara_matches:
                    layers_seen = set()
                    yara_cap = int(self.effective_policy.get("yara_score_cap", 120))
                    for (layer_name, score, rule, description, reference, matched_strings, author) in yara_matches:
                        layers_seen.add(layer_name or "raw")
                        if layer_name == "raw" or not layer_name:
                            local_stats["yara_matches_raw"] = local_stats.get("yara_matches_raw", 0) + 1
                        else:
                            local_stats["yara_matches_deobfuscated"] = (
                                local_stats.get("yara_matches_deobfuscated", 0) + 1)
                        prefix = ""
                        if layer_name and layer_name != "raw":
                            prefix = "Deobfuscated[%s]: " % layer_name
                        delta = self._add_group_score(group_scores, "yara", score, cap=yara_cap)
                        message = "%sYara Rule MATCH: %s SUBSCORE: %s EFFECTIVE_SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s" % (
                            prefix, rule, score, delta, description, reference, author)
                        if matched_strings:
                            message += " MATCHES: %s" % matched_strings
                        if delta:
                            total_score += delta
                            evidence_groups.add("yara")
                        reasons.append(message)
                    local_stats["deobfuscate_layers"] = local_stats.get("deobfuscate_layers", 0) + len(
                        [layer for layer in layers_seen if layer != "raw"])

            except Exception as e:
                logger.log("ERROR", "FileScan", f"Cannot YARA scan file: {filePathCleaned}. Error: {str(e)}")

            fp_gate_reason = library_fp_gate(
                filePath, extension, fileData, evidence_groups, reasons, self.effective_policy)
            if fp_gate_reason and not yara_timeout_occurred:
                if total_score >= self._get_gray_zone_min() and reasons:
                    gray_description = "".join(
                        "REASON_%s: %s\n " % (i + 1, r) for i, r in enumerate(reasons))
                    gray_description += "REASON_%s: FP_GATE: %s\n " % (len(reasons) + 1, fp_gate_reason)
                    self._append_gray_zone_row(
                        filePath, sha256, total_score, getAgeString(filePath), gray_description, extension,
                        is_multiprocessing=is_multiprocessing, result_dict=result_dict)
                logger.log("NOTICE", "FileScan",
                           "Library FP gate: %s (score %s, %s)"
                           % (filePath, total_score, fp_gate_reason))
                return

            if reasons or yara_timeout_occurred:
                reasons.append(self._confidence_summary(total_score, evidence_groups, yara_timeout_occurred))

            fileInfo = "===========================================================\n" \
                       "FILE: %s\n SCORE: %s%s\n %s" % (
                           filePath, total_score, getAgeString(filePath),
                           format_sha256_line(sha256))
            if yara_timeout_occurred:
                fileInfo += "*** YARA SCAN TIMEOUT - REQUIRES MANUAL REVIEW ***\n "

            message_type = "INFO"
            if total_score >= 100:
                message_type = "ALERT"
            elif total_score >= 60:
                message_type = "WARNING"
            elif total_score >= 40:
                message_type = "NOTICE"
            if yara_timeout_occurred and message_type == "INFO":
                message_type = "WARNING"

            min_score = self._get_min_score(args)
            gray_min = self._get_gray_zone_min()
            logger.log(
                "DEBUG", "FileScan",
                "File %s: total_score=%s min_score=%s gray_min=%s reasons=%s yara_timeout=%s"
                % (filePath, total_score, min_score, gray_min, len(reasons), yara_timeout_occurred),
            )

            message_body = fileInfo
            reason_lines = []
            reason_csv_lines = []
            for i, r in enumerate(reasons):
                reason_lines.append("\tREASON_{0}: {1}\n ".format(i + 1, r))
                reason_csv_lines.append("REASON_{0}: {1}\n ".format(i + 1, r))
            message_body += "".join(reason_lines)
            message_csv = "".join(reason_csv_lines)

            single_evidence_gray_reason = self._single_evidence_gray_reason(total_score, evidence_groups)
            if single_evidence_gray_reason and not yara_timeout_occurred:
                if total_score >= gray_min and reasons:
                    gray_description = message_csv + "REASON_%s: FP_GATE: %s\n " % (
                        len(reasons) + 1, single_evidence_gray_reason)
                    self._append_gray_zone_row(
                        filePath, sha256, total_score, getAgeString(filePath), gray_description, extension,
                        is_multiprocessing=is_multiprocessing, result_dict=result_dict)
                    logger.log("NOTICE", "FileScan",
                               "Gray zone by evidence gate: %s (score %s, %s)"
                               % (filePath, total_score, single_evidence_gray_reason))
                else:
                    logger.log("DEBUG", "FileScan",
                               "Skipping file %s by evidence gate (score %s, %s)"
                               % (filePath, total_score, single_evidence_gray_reason))
                return

            if total_score < min_score and not yara_timeout_occurred:
                if total_score >= gray_min and reasons:
                    self._append_gray_zone_row(
                        filePath, sha256, total_score, getAgeString(filePath), message_csv, extension,
                        is_multiprocessing=is_multiprocessing, result_dict=result_dict)
                    logger.log("NOTICE", "FileScan",
                               "Gray zone: %s (score %s)" % (filePath, total_score))
                else:
                    logger.log("DEBUG", "FileScan",
                               "Skipping file %s (score %s < %s)" % (filePath, total_score, min_score))
                return

            logger.log("DEBUG", "FileScan", f"Adding file to report: {filePath}, score={total_score}, message_type={message_type}, reasons={len(reasons)}")

            if args and (getattr(args, 'quarantine', False) or getattr(args, 'quarantine_exact', False)) and total_score >= 100:
                src = filePath
                dst = ""
                try:
                    dst, move_error = self.quarantine_manager.move(
                        src, sha256, exact=getattr(args, 'quarantine_exact', False))
                    if move_error == "source_missing":
                        logger.log("WARNING", "FileScan", f"Source file does not exist: {src}")
                        message_body += "FILE CAN NOT MOVED TO QUARANTINE (source file not found)!!!\n "
                    else:
                        message_body += "FILE MOVED TO QUARANTINE: %s\n " % dst
                except Exception as e:
                    logger.log("ERROR", "FileScan", f"Cannot move file to quarantine {src} -> {dst}: {e}")
                    message_body += "FILE CAN NOT MOVED TO QUARANTINE!!!\n "

            finding_data = {
                'score': total_score,
                'message_type': message_type,
                'message_body': message_body,
                'file': filePath,
                'time': getAgeString(filePath),
                'description': message_csv,
                'extension': extension,
                'sha256': sha256
            }
            
            if is_multiprocessing and result_dict:
                result_dict['findings'].append(finding_data)
            else:
                with self.result_lock:
                    MESSAGE.append([total_score, message_type, message_body])
                self._append_finding_csv_row(
                    filePath, sha256, total_score, getAgeString(filePath), message_csv, extension)
            logger.log("DEBUG", "FileScan", f"Added to MESSAGE and CSV: {filePath}, score={total_score}, has_ssdeep={any('SSDeep' in r for r in reasons)}")

        except Exception as e:
            local_stats["files_errors"] = local_stats.get("files_errors", 0) + 1
            logger.log("ERROR", "FileScan", f"Error processing file {filePath}: {str(e)}")
            traceback.print_exc()
        finally:
            if result_dict is not None:
                result_dict["stats"] = local_stats
            elif local_stats:
                self.scan_stats.merge(local_stats)

    def scan_path(self, path, args=None):
        global MESSAGE, fileInfo_csv, all_files_csv, gray_zone_csv
        MESSAGE = []
        fileInfo_csv = new_findings_report()
        all_files_csv = new_all_files_report()
        gray_zone_csv = new_gray_zone_report()
        self.scan_stats = ScanStats()
        self.scan_stats.set_lock(self.result_lock)
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
        single_file = os.path.isfile(path)

        # Pre-count total files for accurate progress display (exclude paths in excludes.cfg)
        def _precount_files(scan_path):
            if os.path.isfile(scan_path):
                return 1
            counted = 0
            try:
                for root, directories, files in os.walk(scan_path, onerror=self.walk_error, followlinks=False):
                    # Filter directories using startExcludes (same as main loop)
                    newDirectories = []
                    for directory in directories:
                        completePath = os.path.join(root, directory).lower() + os.sep
                        skipDir = any(completePath.startswith(skip) for skip in self.startExcludes)
                        if not skipDir:
                            newDirectories.append(directory)
                    directories[:] = newDirectories
                    
                    for filename in files:
                        filePath = os.path.join(root, filename)
                        skipIt = False
                        for skip in self.fullExcludes:
                            if skip.search(filePath):
                                skipIt = True
                                break
                        if not skipIt and os_platform == "linux":
                            for skip in self.LINUX_PATH_SKIPS_END:
                                if filePath.endswith(skip):
                                    skipIt = True
                                    break
                        if not skipIt:
                            counted += 1
            except Exception as e:
                logger.log("DEBUG", "FileScan", f"Cannot pre-count files in {scan_path}: {str(e)}")
            return counted

        total = _precount_files(path)
        self.processed_files = 0

        num_workers = getattr(args, 'threads', 1) if args else 1
        if num_workers is None or num_workers < 1:
            num_workers = 1

        self.parallel_console = num_workers > 1
        if logger:
            logger.parallel_mode = num_workers > 1
            if num_workers > 1:
                logger.log(
                    "NOTICE", "FileScan",
                    "Quét đa luồng: console chỉ hiển thị tiến độ; chi tiết từng file (kèm [Worker]) ghi vào file log.",
                )

        # Log system information
        cpu_count = get_cpu_count()
        logger.log("INFO", "FileScan", f"System Information: {cpu_count} CPU core(s) detected")
        logger.log("INFO", "FileScan", f"Configured worker count: {num_workers}")
        
        # Với Windows (spawn), đối tượng Scanner/YARA không pickle được -> fallback threading
        use_multiprocessing = num_workers > 1 and os_platform != "windows"
        use_threading = num_workers > 1 and os_platform == "windows"
        
        file_queue = None
        result_queue = None
        progress_counter = None
        workers = []
        if use_multiprocessing:
            # Initialize multiprocessing
            logger.log("INFO", "FileScan", f"Initializing multi-process scanning with {num_workers} worker process(es)")
            logger.log("INFO", "FileScan", "Using multiprocessing for better CPU utilization (bypasses Python GIL)")
            
            # Shared state (avoid Manager to reduce IPC overhead/blocking)
            progress_counter = multiprocessing.Value('i', 0)
            result_queue = multiprocessing.Queue()
            file_queue = multiprocessing.Queue(maxsize=num_workers * 2)
            
            self.use_multiprocessing = True
            self.mp_manager = None
            self.mp_progress_counter = progress_counter
            self.mp_result_queue = result_queue
            
            # Start worker processes
            for i in range(num_workers):
                worker = Process(target=self._worker_process_file,
                                args=(file_queue, args, app_path_lower, total, result_queue, progress_counter),
                                name=f"Worker-{i+1}")
                worker.start()
                workers.append(worker)
                logger.log("INFO", "FileScan", f"Worker process {i+1}/{num_workers} started (PID: {worker.pid}, Name: {worker.name})")
            logger.log("INFO", "FileScan", f"All {num_workers} worker process(es) initialized and ready")
        elif use_threading:
            logger.log("NOTICE", "FileScan", f"Windows spawn detected; using multi-threading instead of multiprocessing")
            logger.log("INFO", "FileScan", f"Initializing multi-threaded scanning with {num_workers} worker thread(s)")
            file_queue = queue.Queue(maxsize=num_workers * 2)
            for i in range(num_workers):
                worker = threading.Thread(target=self._worker_process_file,
                                           args=(file_queue, args, app_path_lower, total, None, None),
                                           name=f"Worker-{i+1}",
                                           daemon=True)
                worker.start()
                workers.append(worker)
                logger.log("INFO", "FileScan", f"Worker thread {i+1}/{num_workers} started (Thread ID: {worker.ident}, Name: {worker.name})")
            logger.log("INFO", "FileScan", f"All {num_workers} worker thread(s) initialized and ready")
        else:
            logger.log("INFO", "FileScan", "Running in single-threaded mode")
            self.use_multiprocessing = False

        def _schedule_file(filePath):
            try:
                if use_multiprocessing or use_threading:
                    # Put file to queue (may block if queue is full, but that's acceptable)
                    file_queue.put(filePath, block=True, timeout=None)
                else:
                    # Single-thread fallback
                    self.process_single_file(filePath, args, app_path_lower, total)
            except Exception as e:
                logger.log("ERROR", "FileScan", f"Error scheduling file {filePath}: {str(e)}")
                traceback.print_exc()

        if single_file:
            logger.log("DEBUG", "FileScan", f"Queueing single file: {path}")
            _schedule_file(path)
        else:
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

                # Loop through files
                if (use_multiprocessing or use_threading) and len(files) > 0:
                    logger.log("DEBUG", "FileScan", f"Queueing {len(files)} file(s) from directory: {root}")
                for filename in files:
                    _schedule_file(os.path.join(root, filename))

        if use_multiprocessing:
            logger.log("INFO", "FileScan", f"All files queued. Waiting for {num_workers} worker process(es) to complete processing...")
            
            # Start result collector thread
            def collect_results(expected_workers):
                """Drain result_queue until we receive the None sentinel.
                If workers crash without sending results, the sentinel is sent by
                the main thread after all workers have joined — so this loop will
                always terminate.
                """
                results_collected = 0
                while True:
                    try:
                        result = result_queue.get(timeout=2)
                        if result is None:  # Shutdown sentinel
                            break

                        # Process result
                        if result.get('all_file_info'):
                            all_file_info = result['all_file_info']
                            with self.result_lock:
                                all_files_csv["FILE"].append(all_file_info['FILE'])
                                all_files_csv["SHA256"].append(all_file_info.get('SHA256', 'N/A'))
                                all_files_csv["TIME_CREATED"].append(all_file_info['TIME_CREATED'])
                                all_files_csv["TIME_MODIFIED"].append(all_file_info['TIME_MODIFIED'])
                                all_files_csv["TIME_ACCESSED"].append(all_file_info['TIME_ACCESSED'])
                                all_files_csv["EXTENSION"].append(all_file_info['EXTENSION'])

                        # Process findings
                        for finding in result.get('findings', []):
                            with self.result_lock:
                                MESSAGE.append([finding['score'], finding['message_type'], finding['message_body']])
                            self._append_finding_csv_row(
                                finding['file'],
                                finding.get('sha256', 'N/A'),
                                finding['score'],
                                finding['time'],
                                finding['description'],
                                finding['extension'])

                        for gz in result.get('gray_zone', []):
                            self._append_gray_zone_row(
                                gz['file'], gz['sha256'], gz['score'], gz['time'],
                                gz['description'], gz['extension'])

                        if result.get("stats"):
                            self.scan_stats.merge(result["stats"])

                        results_collected += 1
                    except Exception:
                        # Queue.get timeout — loop and retry; sentinel will arrive
                        # once main thread puts it after all workers finish.
                        continue

                logger.log("INFO", "FileScan", f"Result collector finished. Collected {results_collected} result(s)")
            
            collector_thread = threading.Thread(target=collect_results, args=(num_workers,), daemon=True)
            collector_thread.start()
            
            # Send shutdown signals
            logger.log("INFO", "FileScan", f"Sending shutdown signals to {num_workers} worker process(es)...")
            for i in range(num_workers):
                file_queue.put(None)
            
            # Wait for all workers to finish
            logger.log("INFO", "FileScan", f"Waiting for all worker process(es) to finish...")
            for i, worker in enumerate(workers, 1):
                worker.join()
                logger.log("INFO", "FileScan", f"Worker process {i}/{num_workers} (PID: {worker.pid}, Name: {worker.name}) has finished")
            
            # Signal result collector to stop — sentinel MUST be sent AFTER all workers finish
            # so the collector has already drained every result before receiving None.
            result_queue.put(None)
            collector_thread.join(timeout=30)
            if collector_thread.is_alive():
                logger.log("WARNING", "FileScan", "Result collector thread did not finish in time — some results may be incomplete")

            logger.log("INFO", "FileScan", f"All {num_workers} worker process(es) have completed successfully")
        elif use_threading:
            logger.log("INFO", "FileScan", f"All files queued. Waiting for {num_workers} worker thread(s) to complete processing...")
            file_queue.join()
            logger.log("INFO", "FileScan", f"All files processed. Sending shutdown signals to {num_workers} worker thread(s)...")
            for i in range(num_workers):
                file_queue.put(None)
            logger.log("INFO", "FileScan", f"Waiting for all worker thread(s) to finish...")
            for i, worker in enumerate(workers, 1):
                worker.join()
                logger.log("INFO", "FileScan", f"Worker thread {i}/{num_workers} ({worker.name}) has finished")
            logger.log("INFO", "FileScan", f"All {num_workers} worker thread(s) have completed successfully")
        
        log_runtime_summary(
            logger, self.scan_stats,
            findings_count=len(MESSAGE),
            gray_zone_count=len(gray_zone_csv.get("FILE", [])),
            all_files_count=len(all_files_csv.get("FILE", [])),
        )

        MESSAGE.sort(key=lambda x: x[0], reverse=True)
        logger.log("INFO", "FileScan", f"Total files to report: {len(MESSAGE)}")
        # Log individual files - DEBUG messages won't print to console
        for i in MESSAGE:
            # Use log() - DEBUG won't print to console, other types will
            logger.log(i[1], "FileScan", i[2])
            # Debug: log summary to see what's being written (file only)
            # Removed - no longer needed

    def scan_data(self, fileData, fileType="-", fileName="-", filePath="-", extension="-", md5="-", timeout=None):
        """
        Scan dữ liệu file với YARA rules.
        fileName và filePath phải là str (không phải bytes).
        """
        # Đảm bảo str — chấp nhận bytes để tương thích ngược
        if isinstance(fileName, bytes):
            fileName = fileName.decode('utf-8', errors='replace')
        if isinstance(filePath, bytes):
            filePath = filePath.decode('utf-8', errors='replace')
        if isinstance(extension, bytes):
            extension = extension.decode('utf-8', errors='replace')

        # Tạo externals dict một lần (tối ưu)
        externals = {
            'filename': fileName,
            'filepath': filePath,
            'extension': extension,
            'filetype': fileType,
            'md5': md5,
            'owner': "dummy"
        }
        
        # Scan with yara
        try:
            for rules in self.yara_rules:
                # Yara Rule Match
                match_kwargs = {'data': fileData, 'externals': externals}
                if timeout:
                    match_kwargs['timeout'] = max(1, int(timeout))
                try:
                    matches = rules.match(**match_kwargs)
                except TypeError:
                    if 'timeout' not in match_kwargs:
                        raise
                    match_kwargs.pop('timeout', None)
                    matches = rules.match(**match_kwargs)

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
                                try:
                                    score = int(meta['score'])
                                except Exception:
                                    logger.log("WARNING", "YARA", "Invalid meta.score in rule %s, using default 70" % match.rule)
                                    score = 70

                        # Matching strings
                        matched_strings = ""
                        if hasattr(match, 'strings'):
                            # Get matching strings
                            matched_strings = self.get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except yara.TimeoutError:
            raise
        except Exception as e:
            logger.log("DEBUG", "YARA", f"Error during YARA scan: {str(e)}")
            pass

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
        Compile từng file riêng để báo đúng file khi có lỗi.
        Các file compile thành công được gộp lại thành một compiled set cuối cùng.
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
        rule_mode = str(self.scan_policy.get("yara_rule_mode", "all")).lower()
        webshell_patterns = [
            str(p).lower()
            for p in self.scan_policy.get("webshell_yara_file_patterns", [])
            if str(p).strip()
        ]

        def include_rule_file(path):
            if rule_mode not in ("webshell-only", "webshell_only", "webshell"):
                return True
            rel = os.path.relpath(path, self.app_path).replace("\\", "/").lower()
            if "/custom/" in rel:
                return True
            return any(pattern in rel for pattern in webshell_patterns)

        # Collect (path, content) for each valid rule file
        rule_files = []

        try:
            for yara_rule_directory in self.yara_rule_directories:
                if not os.path.exists(yara_rule_directory):
                    continue

                for root, directories, files in os.walk(yara_rule_directory, onerror=self.walk_error,
                                                        followlinks=False):
                    for file in files:
                        if not file or file[0] in SKIP_PREFIXES:
                            continue
                        extension = os.path.splitext(file)[1].lower()
                        if extension not in VALID_EXTENSIONS:
                            continue
                        yaraRuleFile = os.path.join(root, file)
                        if not include_rule_file(yaraRuleFile):
                            continue
                        try:
                            with open(yaraRuleFile, 'r', encoding='utf-8', errors='replace') as yfile:
                                yara_rule_data = yfile.read()
                            if yara_rule_data.strip():
                                rule_files.append((yaraRuleFile, yara_rule_data))
                        except UnicodeDecodeError:
                            logger.log("WARNING", "Init",
                                       f"Cannot read file {file} - encoding error, skipping")
                        except Exception as e:
                            logger.log("WARNING", "Init",
                                       f"Error reading signature file {file}: {str(e)}")

            if not rule_files:
                logger.log("ERROR", "Init", "No YARA rule files found!")
                sys.exit(1)

            logger.log("INFO", "Init", f"Found {len(rule_files)} YARA rule file(s). Compiling...")
            if rule_mode in ("webshell-only", "webshell_only", "webshell"):
                logger.log("INFO", "Init", "YARA rule mode: webshell-only")

            # --- Pass 1: validate each file individually to catch per-file errors ---
            valid_contents = []
            skipped_files = []
            for yaraRuleFile, content in rule_files:
                try:
                    yara.compile(source=content, externals=YARA_EXTERNALS)
                    valid_contents.append(content)
                except yara.SyntaxError as e:
                    logger.log("WARNING", "Init",
                               f"Skipping YARA file with syntax error: {yaraRuleFile} — {e}")
                    skipped_files.append(yaraRuleFile)
                except Exception as e:
                    logger.log("WARNING", "Init",
                               f"Skipping YARA file (unexpected error): {yaraRuleFile} — {e}")
                    skipped_files.append(yaraRuleFile)

            if not valid_contents:
                logger.log("ERROR", "Init", "No valid YARA rule files could be compiled!")
                sys.exit(1)

            if skipped_files:
                logger.log("WARNING", "Init",
                           f"Skipped {len(skipped_files)} YARA file(s) with errors: "
                           f"{', '.join(os.path.basename(f) for f in skipped_files)}")

            # --- Pass 2: compile all valid rules together as a single compiled set ---
            combined_source = '\n'.join(valid_contents)
            try:
                compiledRules = yara.compile(source=combined_source, externals=YARA_EXTERNALS)
                total_rules = len(re.findall(r'^\s*rule\s+', combined_source, re.MULTILINE))
                self.yara_rules.append(compiledRules)
                logger.log("INFO", "Init",
                           f"Successfully compiled {total_rules} YARA rule(s) from "
                           f"{len(valid_contents)}/{len(rule_files)} file(s)")
            except yara.SyntaxError as e:
                # Should not happen (each file validated individually), but handle defensively
                error_msg = str(e)
                logger.log("ERROR", "Init",
                           f"Combined YARA compilation failed (unexpected): {error_msg}")
                line_number = self.extract_line_number_from_error(error_msg)
                if line_number:
                    self.print_error_line_context(combined_source, line_number)
                logger.log("ERROR", "Init", "Please fix the YARA rule errors and try again.")
                sys.exit(1)

        except Exception as e:
            logger.log("ERROR", "Init", f"Critical error during YARA rule initialization: {str(e)}")
            traceback.print_exc()
            sys.exit(1)

    def initialize_hash_iocs(self, ioc_directory, false_positive=False):
        ioc_filename = None
        # Whitelist as a set of lowercase hex strings for correct comparison with file_hash (str)
        HASH_WHITELIST = {  # Empty file hashes
            'd41d8cd98f00b204e9800998ecf8427e',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            # One byte line break file (Unix) 0x0a
            '68b329da9893e34099c7d8ad5cb9c940',
            'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
            '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
            # One byte line break file (Windows) 0x0d0a
            '81051bcc2cf1bedf378224b0a93e2877',
            'ba8ab5a0280b953aa97435ff8946cbcbb2755a27',
            '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6',
        }
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if 'hash' in ioc_filename:
                    is_fp_file = 'falsepositive' in ioc_filename.lower()
                    if false_positive and not is_fp_file:
                        continue
                    if not false_positive and is_fp_file:
                        continue
                    with codecs.open(os.path.join(ioc_directory, ioc_filename), 'r',
                                     encoding='utf-8', errors='replace') as file:
                        lines = file.readlines()

                        for line in lines:
                            try:
                                if re.search(r'^#', line) or re.search(r'^\s*$', line):
                                    continue
                                row = line.split(';')
                                file_hash = row[0].strip().lower()
                                if not re.fullmatch(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}', file_hash):
                                    logger.log("WARNING", "Init", "Invalid hash IOC skipped: %s" % line.rstrip())
                                    continue
                                comment = row[1].rstrip(" ").rstrip("\n") if len(row) > 1 else ioc_filename
                                # Empty File Hash
                                if file_hash in HASH_WHITELIST:
                                    continue
                                if false_positive:
                                    self.false_hashes[int(file_hash, 16)] = comment
                                    continue
                                # Else - check which type it is
                                if len(file_hash) == 32:
                                    self.hashes_md5[int(file_hash, 16)] = comment
                                if len(file_hash) == 40:
                                    self.hashes_sha1[int(file_hash, 16)] = comment
                                if len(file_hash) == 64:
                                    self.hashes_sha256[int(file_hash, 16)] = comment
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
            with codecs.open(ioc_file, 'r', encoding='utf-8', errors='replace') as file:
                lines = file.readlines()

                last_comment = ""

                for line in lines:
                    try:
                        if re.search(r'^\s*$', line):
                            continue

                        if re.search(r'^#', line):
                            last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                            continue

                        if ";" not in line:
                            logger.log("WARNING", "Init", "Filename IOC missing score, skipped: %s" % line.rstrip())
                            continue

                        regex_fp = None
                        line = line.rstrip(" ").rstrip("\n\r")
                        row = line.split(';')
                        if len(row) < 2:
                            logger.log("WARNING", "Init", "Filename IOC malformed, skipped: %s" % line.rstrip())
                            continue
                        regex = row[0]
                        try:
                            score = int(row[1])
                        except Exception:
                            logger.log("WARNING", "Init", "Filename IOC invalid score, skipped: %s" % line.rstrip())
                            continue
                        if score <= 0:
                            logger.log("WARNING", "Init", "Filename IOC non-positive score, skipped: %s" % line.rstrip())
                            continue
                        if len(row) > 2 and row[2].strip():
                            regex_fp = row[2]
                        desc = last_comment

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
            logger.log("WARNING", "Init", f"Error reading filename IOC file {ioc_file}: {str(e)}")

    def initialize_hash_iocs_from_file(self, ioc_file, false_positive=False):
        """Đọc hash IOCs từ một file cụ thể."""
        # Whitelist as a set of lowercase hex strings for correct comparison with file_hash (str)
        HASH_WHITELIST = {
            'd41d8cd98f00b204e9800998ecf8427e',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            '68b329da9893e34099c7d8ad5cb9c940',
            'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
            '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
            '81051bcc2cf1bedf378224b0a93e2877',
            'ba8ab5a0280b953aa97435ff8946cbcbb2755a27',
            '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6',
        }
        try:
            with codecs.open(ioc_file, 'r', encoding='utf-8', errors='replace') as file:
                lines = file.readlines()

                for line in lines:
                    try:
                        if re.search(r'^#', line) or re.search(r'^\s*$', line):
                            continue
                        row = line.split(';')
                        file_hash = row[0].strip().lower()
                        if not re.fullmatch(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}', file_hash):
                            logger.log("WARNING", "Init", "Invalid custom hash IOC skipped: %s" % line.rstrip())
                            continue
                        comment = row[1].rstrip(" ").rstrip("\n") if len(row) > 1 else os.path.basename(ioc_file)
                        if file_hash in HASH_WHITELIST:
                            continue
                        if false_positive:
                            self.false_hashes[int(file_hash, 16)] = comment
                            continue
                        if len(file_hash) == 32:
                            self.hashes_md5[int(file_hash, 16)] = comment
                        if len(file_hash) == 40:
                            self.hashes_sha1[int(file_hash, 16)] = comment
                        if len(file_hash) == 64:
                            self.hashes_sha256[int(file_hash, 16)] = comment
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
                    
                    # Store as tuple and index by blocksize for faster compare.
                    self._index_ssdeep_signature(ssdeep_hash, filename)

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

    # Multiprocessing pickling helpers to drop/recreate thread locks
    def __getstate__(self):
        state = self.__dict__.copy()
        # Locks are not pickleable; drop and recreate in child
        state['progress_lock'] = None
        state['result_lock'] = None
        state['quarantine_lock'] = None
        state['quarantine_manager'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.progress_lock = threading.Lock()
        self.result_lock = threading.Lock()
        self.quarantine_lock = threading.Lock()
        self.quarantine_manager = QuarantineManager(self.app_path, self.quarantine_lock)

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
    parser.add_argument('-p', '--path', help='Path to scan (không bắt buộc với --health-check)')
    parser.add_argument('-o', '--out_file', help='Write to file', default=None)
    quarantine_group = parser.add_mutually_exclusive_group()
    quarantine_group.add_argument('-q', '--quarantine', help='Rename and move to quarantine areas', default=False,
                                  action='store_true')
    quarantine_group.add_argument('-qe', '--quarantine-exact',
                                  help='Move to quarantine keeping original filename; rename only on same-name different-hash conflict',
                                  default=False, action='store_true')
    parser.add_argument('-d', '--debug', help='Enable debug mode to show all DEBUG messages on console', 
                        default=False, action='store_true')
    parser.add_argument('-t', '--threads', 
                       help='Number of worker threads for file scanning. Use 0 or "auto" to auto-detect optimal count based on CPU cores. Default: 1 (single-threaded)',
                       default='1')
    parser.add_argument('--min-score', type=int, default=None,
                        help='Minimum score for main findings report (default: from config, usually 40)')
    parser.add_argument('--paranoid', action='store_true',
                        help='Lower thresholds: min-score=25, ssdeep=40, stronger entropy on upload paths')
    parser.add_argument('--health-check', action='store_true',
                        help='Chỉ chạy kiểm tra preflight (YARA, deobfuscate, entropy, SSDeep...) rồi thoát')
    parser.add_argument('--no-ssdeep', action='store_true',
                        help='Tắt so khớp SSDeep/fuzzy hash cho lần chạy này')
    parser.add_argument('--vt-ssdeep', action='store_true',
                        help='Sau quét: mở VirusTotal trên trình duyệt; nếu báo mã độc thì thêm vào known_webshells.ssdeep')
    parser.add_argument('--no-review-bundle', action='store_true',
                        help='Không tạo file .enc để import vào review web')
    args = parser.parse_args()

    if args.health_check:
        args.path = args.path or os.getcwd()
    elif not args.path:
        parser.error("Cần -p/--path để quét (hoặc dùng --health-check chỉ kiểm tra module)")

    # Parse threads argument - support "auto", "0", or integer (as string or int)
    threads_input = str(args.threads).lower().strip()
    
    if threads_input in ['auto', '0']:
        # Auto-detect optimal thread count
        optimal_threads, cpu_count, recommendation = get_optimal_thread_count()
        args.threads = optimal_threads
        print(f"\n[INFO] Auto-detecting optimal thread count...")
        print(f"[INFO] {recommendation}")
        print(f"[INFO] Using {args.threads} thread(s) for scanning\n")
    else:
        try:
            args.threads = int(threads_input)
            if args.threads < 1:
                parser.error("--threads must be >= 1, or use 'auto'/'0' for auto-detection")
        except ValueError:
            parser.error(f"Invalid --threads value: '{args.threads}'. Use an integer >= 1, or 'auto'/'0' for auto-detection")
    
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
            
            # Làm sạch tên thư mục: bỏ ký tự đặc biệt
            # Thay thế các ký tự không hợp lệ trong tên file
            invalid_chars = '<>:"/\\|?*'
            for char in invalid_chars:
                scan_dir_name = scan_dir_name.replace(char, '_')
            
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
    # Set multiprocessing start method (required for Windows, optional for Linux)
    # On Windows, 'spawn' is the only method available
    # On Linux, 'fork' is faster but 'spawn' is safer
    try:
        if os_platform == "windows":
            multiprocessing.set_start_method('spawn', force=True)
        else:
            # Try fork first (faster), fallback to spawn if not available
            try:
                multiprocessing.set_start_method('fork', force=True)
            except (RuntimeError, ValueError):
                multiprocessing.set_start_method('spawn', force=True)
    except (RuntimeError, ValueError):
        # Start method already set, or not available - continue anyway
        pass

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
    scanner.apply_runtime_policy(args)

    if args.health_check:
        logger.log("NOTICE", "Health", "Health-check hoàn tất — xem log [Health] phía trên.")
        logger.close()
        sys.exit(0)

    # Check if admin
    isRoot = False
    if os_platform == "windows":
        if shell is not None and shell.IsUserAnAdmin():
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

    if scanner.effective_policy.get("vt_ssdeep_enabled"):
        scanner.run_vt_ssdeep_feed(args=args)

    # Result ----------------------------------------------------------
    logger.log_to_csv_file(fileInfo_csv, column_order=FINDINGS_REPORT_COLUMNS)
    logger.log_all_files_to_excel(all_files_csv, column_order=ALL_FILES_REPORT_COLUMNS)
    logger.log_gray_zone_to_excel(gray_zone_csv, column_order=GRAY_ZONE_REPORT_COLUMNS)
    if gray_zone_csv.get("FILE"):
        logger.log("NOTICE", "Results",
                   "Gray zone report: %s gray_zone_%s.xlsx (%s entries)"
                   % (scanner.get_application_path() + "/logs/".replace("/", os.sep),
                      args.out_file, len(gray_zone_csv["FILE"])))

    if not getattr(args, "no_review_bundle", False):
        try:
            passphrase = bundle_passphrase(scanner.get_application_path(), create_if_missing=True)
            review_zip, bundle_stats = build_review_zip(
                findings_report=fileInfo_csv,
                findings_columns=FINDINGS_REPORT_COLUMNS,
                all_files_report=all_files_csv,
                all_files_columns=ALL_FILES_REPORT_COLUMNS,
                gray_zone_report=gray_zone_csv,
                gray_zone_columns=GRAY_ZONE_REPORT_COLUMNS,
                scan_path=defaultPath,
                out_file=args.out_file,
                scanner_version=VERSION,
                yara_rules=scanner.yara_rules,
                scan_policy=scanner.effective_policy,
            )
            enc_path = os.path.join(scanner.get_application_path(), "logs", args.out_file + ".enc")
            write_review_bundle(enc_path, review_zip, passphrase)
            logger.log(
                "NOTICE", "Results",
                "Review web bundle: %s (findings=%s, sources=%s, full_sources=%s, snippet_sources=%s, omitted_sources=%s)"
                % (
                    enc_path,
                    bundle_stats.get("findings", 0),
                    bundle_stats.get("sources", 0),
                    bundle_stats.get("sources_full", 0),
                    bundle_stats.get("sources_snippet", 0),
                    bundle_stats.get("sources_omitted", 0),
                ),
            )
        except Exception as exc:
            logger.log("ERROR", "Results", "Cannot create review .enc bundle: %s" % exc)

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
    logger.log("NOTICE", "Health",
               "Xem log [Health] và [Init] để kiểm tra từng module; tìm ERROR/WARNING nếu thiếu phát hiện.")

    # Flush and close the persistent log file handle
    logger.close()
    sys.exit(0)
