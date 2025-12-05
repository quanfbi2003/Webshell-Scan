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


# Logger Class -----------------------------------------------------------------
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
        sys.exit(1)


def Format(message, *args):
    return message.format(*args)


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
        self._log_lock = threading.Lock()
        
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

    def log(self, mes_type, module, message):
        """
        Log message to file. Also print to console if mes_type is not DEBUG.
        All log types are written to file, but only non-DEBUG logs are printed to console.
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

            # Always write to file
            self.log_to_file(message, mes_type, module)

            # Print to stdout only if not DEBUG (or if debug_mode is enabled)
            if mes_type != "DEBUG" or self.debug_mode:
                try:
                    log_to_stdout(message, mes_type)
                except Exception:
                    print("Cannot print certain characters to command line - see log file for full unicode encoded log line")
                    try:
                        log_to_stdout(message, mes_type)
                    except Exception:
                        pass

    def log_to_csv_file(self, message):
        df = pd.DataFrame(message)
        df.to_excel(self.log_file + ".xlsx", index=True)

    def log_to_file(self, message, mes_type, module):
        """
        Write log message to file with standardized format: [mes_type] module: message
        """
        try:
            # Format message with [mes_type] prefix and module
            formatted_message = u"[{0}] {1}: {2}".format(mes_type, module, message) if module else u"[{0}] {1}".format(mes_type, message)
            with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                logfile.write(Format(u"{0}{1}\n", formatted_message, self.linesep))
        except Exception:
            traceback.print_exc()
            print("Cannot print line to log file {0}".format(self.log_file))
            exit(1)
    
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
            with codecs.open(self.log_file, "w", encoding='utf-8') as logfile:
                pass
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
