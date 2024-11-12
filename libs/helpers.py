#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Simple IOC Scanner

import hashlib
import os
import re
import string
import sys

import psutil

try:
    from StringIO import StringIO  # Python 2
except ImportError:
    from io import StringIO  # Python 3
import netaddr
import platform
import time
import threading
import subprocess
import signal


# Helper Functions -------------------------------------------------------------

def is_ip(string):
    try:
        if netaddr.valid_ipv4(string):
            return True
        if netaddr.valid_ipv6(string):
            return True
        return False
    except:
        # traceback.print_exc()
        return False


def is_cidr(string):
    try:
        if netaddr.IPNetwork(string) and "/" in string:
            return True
        return False
    except:
        return False


def ip_in_net(ip, network):
    try:
        # print "Checking if ip %s is in network %s" % (ip, network)
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(network):
            return True
        return False
    except:
        return False


def generateHashes(filedata):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception:
        # traceback.print_exc()
        return 0, 0, 0


def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % (
            " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception:
        type_info = " ".join(platform.win32_ver())
    return type_info


def setNice(logger):
    try:
        pid = os.getpid()
        p = psutil.Process(pid)
        logger.log("INFO", "Init", "Setting process with PID: %s to priority IDLE" % pid)
        p.nice(psutil.IDLE_PRIORITY_CLASS)
        return 1
    except Exception:
        # traceback.print_exc()
        logger.log("ERROR", "Init", "Error setting nice value of THOR process")
        return 0


def getExcludedMountpoints():
    global mtab
    excludes = []
    try:
        mtab = open("/etc/mtab", "r")
        for mpoint in mtab:
            options = mpoint.split(" ")
            if not options[0].startswith("/dev/"):
                if not options[1] == "/":
                    excludes.append(options[1])
    except Exception:
        print("Error while reading /etc/mtab")
    finally:
        mtab.close()
    return excludes


def removeBinaryZero(string):
    return re.sub(r'\x00', '', string)


def print_progress(i, total):
    sys_inf = "\tRAM: {}%".format(str(psutil.virtual_memory()[2]))
    if (i % 4) == 0:
        sys.stdout.write("\r{} /{} {}".format(str(i), str(total), sys_inf))
        sys.stdout.flush()
    elif (i % 4) == 1:
        sys.stdout.write("\r{} -{} {}".format(str(i), str(total), sys_inf))
        sys.stdout.flush()
    elif (i % 4) == 2:
        sys.stdout.write("\r{} |{} {}".format(str(i), str(total), sys_inf))
        sys.stdout.flush()
    elif (i % 4) == 3:
        sys.stdout.write("\r{} \\{} {}".format(str(i), str(total), sys_inf))
        sys.stdout.flush()


def transformOS(regex, platform):
    # Replace '\' with '/' on Linux/Unix/OSX
    if platform != "windows":
        regex = regex.replace(r'\\', r'/')
        regex = regex.replace(r'C:', '')
    return regex


def replaceEnvVars(path):
    # Setting new path to old path for default
    new_path = path

    # ENV VARS ----------------------------------------------------------------
    # Now check if an environment env is included in the path string
    res = re.search(r"([@]?%[A-Za-z_]+%)", path)
    if res:
        env_var_full = res.group(1)
        env_var = env_var_full.replace("%", "").replace("@", "")

        # Check environment variables if there is a matching var
        if env_var in os.environ:
            if os.environ[env_var]:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))

    # TYPICAL REPLACEMENTS ----------------------------------------------------
    if path[:11].lower() == "\\systemroot":
        new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

    if path[:8].lower() == "system32":
        new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])

    return new_path


def get_file_type(filePath, filetype_sigs, max_filetype_magics, logger):
    try:
        # Reading bytes from file
        with open(filePath, 'rb', os.O_RDONLY) as f:
            res_full = f.read(max_filetype_magics)
        # Checking sigs
        for sig in filetype_sigs:
            bytes_to_read = int(len(str(sig)) / 2)
            res = res_full[:bytes_to_read]
            if res == sig.decode("hex"):
                return filetype_sigs[sig]
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def removeNonAscii(s, stripit=False):
    try:
        printable = set(string.printable)
        filtered_string = filter(lambda x: x in printable, s)
        return ''.join(filtered_string)
    except Exception:
        # traceback.print_exc()
        return s.encode('hex')


def getAge(filePath):
    try:
        stats = os.stat(filePath)

        # Created
        ctime = stats.st_ctime
        # Modified
        mtime = stats.st_mtime
        # Accessed
        atime = stats.st_atime

    except Exception:
        # traceback.print_exc()
        return (0, 0, 0)

    return (ctime, mtime, atime)


def getAgeString(filePath):
    (ctime, mtime, atime) = getAge(filePath)
    try:
        timestring = "\n CREATED: %s MODIFIED: %s ACCESSED: %s" % (time.ctime(ctime), time.ctime(mtime), time.ctime(atime))
    except Exception:
        timestring = "\n CREATED: not_available MODIFIED: not_available ACCESSED: not_available"
    return timestring


def runProcess(command, timeout=10):
    """
    Run a process and check its output
    :param command:
    :return output:
    """
    output = ""
    returnCode = 0

    try:
        kill_check = threading.Event()

        def _kill_process_after_a_timeout(pid):
            os.kill(pid, signal.SIGTERM)
            kill_check.set()  # tell the main routine that we had to kill
            print("timeout hit - killing pid {0}".format(pid))
            # use SIGKILL if hard to kill...
            return "", 1

        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            returnCode = e.returncode
            # traceback.print_exc()

        pid = p.pid
        watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid,))
        watchdog.start()
        stdout, stderr = p.communicate()
        output = "{}{}".format(stdout, stderr)
        watchdog.cancel()  # if it's still waiting to run
        success = not kill_check.isSet()
        kill_check.clear()
    except Exception:
        # traceback.print_exc()
        pass

    return output, returnCode


def getHostname(os_platform):
    """
    Generate and return a hostname
    :return:
    """
    if os_platform == "linux" or os_platform == "macos":
        return os.uname()[1]
    else:
        return os.environ['COMPUTERNAME']
