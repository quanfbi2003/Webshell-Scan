import codecs
import datetime
import os
import re
import sys
import traceback
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
        colorer = re.compile('([A-Z_0-9]{2,}:)\s', re.VERBOSE)
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

    def __init__(self, hostname, platform,  caller, log_file="output.log", VERSION=""):
        self.hostname = hostname
        self.caller = caller
        self.log_file = "logs/".replace("/", os.sep) + log_file
        if "windows" in platform.lower():
            self.linesep = "\r\n"

        # Colorization ----------------------------------------------------
        init()

        self.print_welcome(VERSION)

    def log(self, mes_type, module, message):
        # Counter
        if mes_type == "ALERT":
            self.alerts += 1
        if mes_type == "WARNING":
            self.warnings += 1
        if mes_type == "NOTICE":
            self.notices += 1
        self.messagecount += 1

        # to file
        self.log_to_file(message, mes_type, module)

        # to stdout
        try:
            log_to_stdout(message, mes_type)
        except Exception:
            print("Cannot print certain characters to command line - see log file for full unicode encoded log line")
            log_to_stdout(message, mes_type)

    def log_to_csv_file(self, message):
        df = pd.DataFrame(message)
        df.to_excel(self.log_file + ".xlsx", index=True)

    def log_to_file(self, message, mes_type, module):
        if mes_type == "INFO":
            return # no logging for INFO messages
        try:
            # Write to file - Pending
            with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                logfile.write(Format(u"{0}{1}\n", message, self.linesep))
        except Exception:
            traceback.print_exc()
            print("Cannot print line to log file {0}".format(self.log_file))
            exit(1)

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
