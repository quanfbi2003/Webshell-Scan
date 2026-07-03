import codecs
import datetime
import os
import re
import sys
import traceback
import threading
import pandas as pd
from colorama import Fore, Back, Style
from colorama import init

# Khóa chung cho console (tránh đan xen print giữa các thread)
_console_lock = threading.RLock()
_scan_context = threading.local()


def set_log_worker_tag(tag):
    _scan_context.worker_tag = tag


def clear_log_worker_tag():
    _scan_context.worker_tag = None


class console_lock(object):
    """Context manager: khóa stdout khi in tiến độ / log console."""

    def __enter__(self):
        _console_lock.acquire()
        return self

    def __exit__(self, *args):
        _console_lock.release()


def _lock_log_file(handle):
    # Windows chỉ dùng threading (không multiprocessing worker); RLock đủ cho file.
    if os.name == 'nt':
        return
    try:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        pass


def _unlock_log_file(handle):
    if os.name == 'nt':
        return
    try:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


# Logger Class -----------------------------------------------------------------
def _safe_console_text(text):
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        return str(text).encode(encoding, errors="replace").decode(encoding, errors="replace")
    except Exception:
        return str(text).encode("ascii", errors="replace").decode("ascii")


def log_to_stdout(message, mes_type):
    try:
        reset_all = Style.NORMAL + Fore.RESET
        key_color = Fore.WHITE
        base_color = Back.BLACK + Fore.WHITE
        high_color = Fore.WHITE + Back.BLACK

        if mes_type == "NOTICE":
            base_color = Fore.CYAN + '' + Back.BLACK
            high_color = Fore.BLACK + '' + Back.CYAN
        elif mes_type == "INFO":
            base_color = Fore.GREEN + '' + Back.BLACK
            high_color = Fore.BLACK + '' + Back.GREEN
        elif mes_type == "WARNING":
            base_color = Fore.YELLOW + '' + Back.BLACK
            high_color = Fore.BLACK + '' + Back.YELLOW
        elif mes_type == "ALERT":
            base_color = Fore.RED + '' + Back.BLACK
            high_color = Fore.BLACK + '' + Back.RED
        elif mes_type == "DEBUG":
            base_color = Fore.WHITE + '' + Back.BLACK
            high_color = Fore.BLACK + '' + Back.WHITE
        elif mes_type == "ERROR":
            base_color = Fore.MAGENTA + '' + Back.BLACK
            high_color = Fore.WHITE + '' + Back.MAGENTA
        elif mes_type == "RESULT":
            if "clean" in message.lower():
                high_color = Fore.BLACK + Back.GREEN
                base_color = Fore.GREEN + Back.BLACK
            elif "suspicious" in message.lower():
                high_color = Fore.BLACK + Back.YELLOW
                base_color = Fore.YELLOW + Back.BLACK
            else:
                high_color = Fore.BLACK + Back.RED
                base_color = Fore.RED + Back.BLACK

        # Colorize Type Word at the beginning of the line
        type_colorer = re.compile(r'([A-Z]{3,})', re.VERBOSE)
        mes_type = type_colorer.sub(high_color + r'[\1]' + base_color, mes_type)
        # Break Line before REASONS
        linebreaker = re.compile("(MD5:|SHA1:|SHA256:|MATCHES:|FILE:|FIRST_BYTES:|DESCRIPTION:|REASON_[0-9]+)",
                                 re.VERBOSE)
        message = linebreaker.sub(r'\n\1', message)
        # Colorize Key Words
        colorer = re.compile(r'([A-Z_0-9]{2,}):\s', re.VERBOSE)
        message = colorer.sub(key_color + Style.BRIGHT + r'\1 ' + base_color + Style.NORMAL, message)
        message = _safe_console_text(message)

        # Print to console
        if mes_type == "RESULT":
            res_message = "\b\b%s %s" % (mes_type, message)
            print(base_color + ' ' + res_message + ' ' + Back.BLACK)
            print(Fore.WHITE + ' ' + Style.NORMAL)
        else:
            sys.stdout.write("%s%s\b\b%s %s%s%s%s\n" % (
                reset_all, base_color, mes_type, message, Back.BLACK, Fore.WHITE, Style.NORMAL))

    except Exception:
        traceback.print_exc()
        print("Cannot print to cmd line - formatting error")


def Format(message, *args):
    return message.format(*args)


REPORT_SHA256_COLUMN = "SHA256"


def prepare_report_dataframe(message, column_order=None):
    """
    Build a DataFrame for Excel export, always including a SHA256 column.
    """
    data = dict(message) if message else {}
    if REPORT_SHA256_COLUMN not in data:
        data[REPORT_SHA256_COLUMN] = []
    row_count = max((len(v) for v in data.values() if isinstance(v, list)), default=0)
    if row_count and len(data.get(REPORT_SHA256_COLUMN, [])) < row_count:
        data[REPORT_SHA256_COLUMN].extend(
            ["N/A"] * (row_count - len(data[REPORT_SHA256_COLUMN]))
        )
    if column_order:
        ordered = {}
        for key in column_order:
            if key in data:
                ordered[key] = data[key]
        for key, value in data.items():
            if key not in ordered:
                ordered[key] = value
        data = ordered
    return pd.DataFrame(data)


class Logger:
    STDOUT_CSV = 0
    STDOUT_LINE = 1
    FILE_CSV = 2
    FILE_LINE = 3
    SYSLOG_LINE = 4

    log_file = ""
    hostname = "NOTSET"
    alerts = 0
    csv = True
    warnings = 0
    notices = 0
    messagecount = 0
    linesep = "\n"
    debug_mode = False

    def __init__(self, hostname, platform,  caller, log_file="output.log", VERSION="", debug_mode=False):
        self.hostname = hostname
        self.caller = caller
        self.log_file = "logs/".replace("/", os.sep) + log_file
        self.debug_mode = debug_mode
        self._log_lock = threading.RLock()
        self._file_handle = None  # Persistent file handle (buffered writes)
        self.parallel_mode = False
        
        # Tạo thư mục logs nếu chưa tồn tại
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception as e:
                print(f"Warning: Cannot create log directory {log_dir}: {e}")
        
        if "windows" in platform.lower():
            self.linesep = "\r\n"

        # Colorization ----------------------------------------------------
        init()

        self.print_welcome(VERSION)

    def log(self, mes_type, module, message, worker_tag=None):
        """
        Log message to file. Also print to console if mes_type is not DEBUG.
        Ghi file dùng file-lock (an toàn đa process); console dùng _console_lock.
        """
        worker_tag = worker_tag or getattr(_scan_context, 'worker_tag', None)
        if worker_tag:
            message = "[%s] %s" % (worker_tag, message)

        with self._log_lock:
            if mes_type == "ALERT":
                self.alerts += 1
            if mes_type == "WARNING":
                self.warnings += 1
            if mes_type == "NOTICE":
                self.notices += 1
            self.messagecount += 1

            self.log_to_file(message, mes_type, module)

            show_console = (mes_type != "DEBUG" or self.debug_mode)
            if self.parallel_mode and mes_type == "DEBUG":
                show_console = False
            if self.parallel_mode and module == "FileScan" and mes_type == "INFO":
                show_console = False

            if show_console:
                with _console_lock:
                    try:
                        log_to_stdout(message, mes_type)
                    except Exception:
                        print("Cannot print certain characters to command line - see log file for full unicode encoded log line")
                        try:
                            log_to_stdout(message, mes_type)
                        except Exception:
                            pass

    def log_to_csv_file(self, message, column_order=None):
        df = prepare_report_dataframe(message, column_order=column_order)
        df.to_excel(self.log_file + ".xlsx", index=True)

    def log_all_files_to_excel(self, message, column_order=None):
        """
        Xuất toàn bộ danh sách file đã quét ra Excel với tiền tố 'all file '.
        """
        df = prepare_report_dataframe(message, column_order=column_order)
        log_dir = os.path.dirname(self.log_file)
        base_name = os.path.basename(self.log_file)
        output_path = os.path.join(log_dir, f"all file {base_name}.xlsx")
        df.to_excel(output_path, index=True)

    def log_gray_zone_to_excel(self, message, column_order=None):
        """Xuất báo cáo vùng xám (score giữa gray_zone_min và min_score)."""
        if not message or not message.get("FILE"):
            return
        df = prepare_report_dataframe(message, column_order=column_order)
        log_dir = os.path.dirname(self.log_file)
        base_name = os.path.basename(self.log_file)
        output_path = os.path.join(log_dir, "gray_zone_%s.xlsx" % base_name)
        df.to_excel(output_path, index=True)

    def log_to_file(self, message, mes_type, module):
        """
        Write log message to file with standardized format: [mes_type] module: message
        Uses a persistent file handle to avoid open/close overhead on every log line.
        """
        try:
            formatted_message = u"[{0}] {1}: {2}".format(mes_type, module, message) if module else u"[{0}] {1}".format(mes_type, message)
            line = Format(u"{0}{1}\n", formatted_message, self.linesep)
            # Open file handle lazily and keep it open for the lifetime of the logger
            if self._file_handle is None or self._file_handle.closed:
                self._file_handle = codecs.open(self.log_file, "a", encoding='utf-8')
            _lock_log_file(self._file_handle)
            try:
                self._file_handle.write(line)
                self._file_handle.flush()
            finally:
                _unlock_log_file(self._file_handle)
        except Exception:
            traceback.print_exc()
            with _console_lock:
                print("Cannot print line to log file {0}".format(self.log_file))
            exit(1)

    def close(self):
        """Close the persistent log file handle. Call when scanning is complete."""
        if self._file_handle and not self._file_handle.closed:
            try:
                self._file_handle.flush()
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
    
    def log_file_only(self, mes_type, module, message):
        """
        Log to file only, not to stdout. Also updates counters.
        This method is kept for backward compatibility but is equivalent to log() for DEBUG messages.
        For non-DEBUG messages, use log() instead.
        """
        with self._log_lock:
            # Counter
            if mes_type == "ALERT":
                self.alerts += 1
            if mes_type == "WARNING":
                self.warnings += 1
            if mes_type == "NOTICE":
                self.notices += 1
            self.messagecount += 1
            
            # Write to file only (no console output)
            self.log_to_file(message, mes_type, module)

    def print_welcome(self, VERSION):
        if self.caller == 'main':
            # Truncate (create fresh) the log file and open the persistent handle
            self._file_handle = codecs.open(self.log_file, "w", encoding='utf-8')
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Style.BRIGHT)

            print("   Webshell Scanner " + VERSION + "    ")
            print("  ")
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Fore.GREEN)
            print(Fore.WHITE + '' + Back.BLACK)


def getSyslogTimestamp():
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y%m%dT%H:%M:%SZ")
    return date_str
