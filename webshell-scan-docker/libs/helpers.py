#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
#
#  Simple IOC Scanner

import hashlib
import os
import re
import string
import sys

import psutil

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import netaddr
import platform
import time
import threading
import subprocess
import signal
import socket


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


def generateHashes(filedata, logger=None):
    """
    Generate MD5, SHA1, and SHA256 hashes for file data.
    Returns tuple of (md5, sha1, sha256) hex strings, or ("0", "0", "0") on error.
    :param filedata: file data bytes
    :param logger: optional logger instance for error logging
    """
    try:
        if not filedata:
            # Return empty string hashes for empty data (consistent with error case)
            return "0", "0", "0"
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception as e:
        if logger:
            logger.log("DEBUG", "Helpers", f"Error generating hashes: {str(e)}")
        # Return string "0" instead of integer 0 to avoid TypeError when converting to int with base 16
        return "0", "0", "0"


def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % (
            " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception:
        type_info = " ".join(platform.win32_ver())
    return type_info


def setNice(logger):
    """
    Set process priority to IDLE on Windows.
    Returns 1 on success, 0 on failure.
    """
    try:
        pid = os.getpid()
        p = psutil.Process(pid)
        logger.log("INFO", "Init", "Setting process with PID: %s to priority IDLE" % pid)
        p.nice(psutil.IDLE_PRIORITY_CLASS)
        return 1
    except Exception as e:
        # traceback.print_exc()
        logger.log("ERROR", "Init", f"Error setting nice value of process: {str(e)}")
        return 0


def getExcludedMountpoints(logger=None):
    """
    Get excluded mountpoints from /etc/mtab
    :param logger: optional logger instance for error logging
    :return: list of excluded mountpoint paths
    """
    excludes = []
    mtab = None
    try:
        mtab = open("/etc/mtab", "r")
        for mpoint in mtab:
            options = mpoint.split(" ")
            if len(options) >= 2:
                if not options[0].startswith("/dev/"):
                    if not options[1] == "/":
                        excludes.append(options[1])
        if logger:
            logger.log("DEBUG", "Helpers", f"Found {len(excludes)} excluded mountpoints")
    except Exception as e:
        error_msg = f"Error while reading /etc/mtab: {str(e)}"
        print(error_msg)
        if logger:
            logger.log("WARNING", "Helpers", error_msg)
    finally:
        if mtab:
            try:
                mtab.close()
            except Exception:
                pass
    return excludes


def removeBinaryZero(string):
    return re.sub(r'\x00', '', string)


def get_cpu_count():
    """
    Get the number of CPU cores available on the system.
    Returns the number of logical CPUs (including hyperthreading).
    """
    try:
        # Try os.cpu_count() first (Python 3.4+)
        cpu_count = os.cpu_count()
        if cpu_count is not None:
            return cpu_count
    except AttributeError:
        pass
    
    try:
        # Fallback to multiprocessing
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        if cpu_count is not None:
            return cpu_count
    except Exception:
        pass
    
    try:
        # Fallback to psutil if available
        cpu_count = psutil.cpu_count(logical=True)
        if cpu_count is not None:
            return cpu_count
    except Exception:
        pass
    
    # Default fallback
    return 1


def get_optimal_thread_count(cpu_count=None, logger=None):
    """
    Calculate optimal number of threads for I/O-bound tasks like file scanning.
    
    For I/O-bound tasks, we can use more threads than CPU cores because threads
    spend time waiting for I/O operations. A common formula is:
    - CPU-bound: threads = cpu_count
    - I/O-bound: threads = cpu_count * 2 (or cpu_count + 4 for small systems)
    
    Args:
        cpu_count: Number of CPU cores (if None, will auto-detect)
        logger: Optional logger instance for logging
    
    Returns:
        tuple: (optimal_threads, cpu_count, recommendation_message)
    """
    if cpu_count is None:
        cpu_count = get_cpu_count()
    
    # For file scanning (I/O-bound), we can use more threads than CPU cores
    # because threads spend time waiting for I/O operations (disk reads, YARA scans, etc.)
    # Formula explanation:
    # - Small systems (≤2 cores): Use 2x cores to maximize I/O overlap
    # - Medium systems (3-4 cores): Add 2 extra threads for I/O waiting
    # - Large systems (>4 cores): Use cpu_count * 2, but cap at reasonable limit
    #   to avoid excessive context switching overhead
    if cpu_count <= 2:
        optimal_threads = cpu_count * 2  # 1 core -> 2 threads, 2 cores -> 4 threads
    elif cpu_count <= 4:
        optimal_threads = cpu_count + 2  # 3 cores -> 5 threads, 4 cores -> 6 threads
    else:
        # For larger systems, use cpu_count * 2 but cap at 32 threads max
        # to balance performance and overhead (too many threads cause context switching overhead)
        optimal_threads = min(cpu_count * 2, 32)
    
    # Ensure at least 1 thread
    optimal_threads = max(1, optimal_threads)
    
    recommendation = f"Detected {cpu_count} CPU core(s). Recommended threads: {optimal_threads} (I/O-bound task optimization)"
    
    if logger:
        logger.log("INFO", "System", f"CPU Information: {cpu_count} logical core(s) detected")
        logger.log("INFO", "System", f"Optimal thread count for file scanning: {optimal_threads} (recommended)")
    
    return optimal_threads, cpu_count, recommendation


def print_progress(i, total, logger=None):
    """
    Print progress indicator with animated spinner and RAM usage.
    Optionally log progress milestones to logger.
    :param i: current file index
    :param total: total number of files
    :param logger: optional logger instance for logging milestones
    """
    try:
        # Get RAM usage with error handling
        ram_percent = None
        try:
            ram_percent = psutil.virtual_memory()[2]
            sys_inf = f"\tRAM: {ram_percent:.1f}%"
        except Exception as e:
            sys_inf = "\tRAM: N/A"
            if logger:
                logger.log("DEBUG", "Helpers", f"Error getting RAM usage: {str(e)}")
        
        # Handle division by zero
        if total == 0:
            total = 1  # Avoid division by zero
        
        # Calculate percentage
        percent = (i / total) * 100 if total > 0 else 0
        
        # Animated spinner based on counter
        spinner_chars = ['/', '-', '|', '\\']
        spinner = spinner_chars[i % 4]
        
        # Format progress string
        progress_str = f"{i}/{total} ({percent:.1f}%) {spinner}{sys_inf}"
        
        # Print with carriage return to overwrite previous line
        print("\r" + progress_str, end="\t", flush=True)

    except Exception as e:
        # Log error if logger available
        if logger:
            logger.log("WARNING", "Helpers", f"Error in print_progress: {str(e)}")
        # Fallback: simple progress without RAM info
        try:
            print(f"\r{i}/{total}", end="\t", flush=True)
        except Exception:
            pass  # Silently fail if even basic print fails


def transformOS(regex, platform):
    # Replace '\' with '/' on Linux/Unix/OSX
    if platform != "windows":
        regex = regex.replace(r'\\', r'/')
        regex = regex.replace(r'C:', '')
    return regex


def replaceEnvVars(path):
    """
    Replace environment variables in path string.
    Supports %VAR% and @VAR@ formats, and Windows-specific paths.
    """
    # Setting new path to old path for default
    new_path = path

    try:
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
        if len(path) >= 11 and path[:11].lower() == "\\systemroot":
            if "SystemRoot" in os.environ:
                new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

        if len(path) >= 8 and path[:8].lower() == "system32":
            if "SystemRoot" in os.environ:
                new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])
    except Exception:
        # If replacement fails, return original path
        pass

    # if path != new_path:
    #    print "OLD: %s NEW: %s" % (path, new_path)
    return new_path


def get_file_type(filePath, filetype_sigs, max_filetype_magics, logger):
    try:
        # Reading bytes from file
        with open(filePath, 'rb') as f:
            res_full = f.read(max_filetype_magics)
        # Checking sigs
        for sig in filetype_sigs:
            try:
                bytes_to_read = int(len(str(sig)) / 2)
                res = res_full[:bytes_to_read]
                if res == bytes.fromhex(sig):
                    return filetype_sigs[sig]
            except (ValueError, TypeError) as e:
                # Invalid hex string or type error - skip this signature
                if logger:
                    logger.log("DEBUG", "Helpers", f"Invalid signature format in get_file_type: {str(e)}")
                continue
        return "UNKNOWN"
    except Exception as e:
        if logger:
            logger.log("DEBUG", "Helpers", f"Error determining file type for {filePath}: {str(e)}")
        return "UNKNOWN"


def removeNonAscii(s, stripit=False):
    nonascii = "error"
    try:
        try:
            printable = set(string.printable)
            filtered_string = filter(lambda x: x in printable, s.decode('utf-8'))
            nonascii = ''.join(filtered_string)
        except Exception:
            # traceback.print_exc()
            nonascii = s.hex()
    except Exception:
        # traceback.print_exc()
        pass

    return nonascii


def removeNonAsciiDrop(s):
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        printable = set(string.printable)
        nonascii = filter(lambda x: x in printable, s)
    except Exception:
        pass
    return nonascii


def getAge(filePath, logger=None):
    """
    Get file age information (created, modified, accessed times)
    :param filePath: path to file
    :param logger: optional logger instance for error logging
    :return: tuple of (ctime, mtime, atime) or (0, 0, 0) on error
    """
    try:
        stats = os.stat(filePath)

        # Created
        ctime = stats.st_ctime
        # Modified
        mtime = stats.st_mtime
        # Accessed
        atime = stats.st_atime

    except Exception as e:
        if logger:
            logger.log("DEBUG", "Helpers", f"Error getting file age for {filePath}: {str(e)}")
        return (0, 0, 0)

    # print "%s %s %s" % ( ctime, mtime, atime )
    return (ctime, mtime, atime)


def getAgeString(filePath):
    (ctime, mtime, atime) = getAge(filePath)
    timestring = ""
    try:
        timestring = "\n CREATED: %s MODIFIED: %s ACCESSED: %s" % (time.ctime(ctime), time.ctime(mtime), time.ctime(atime))
    except Exception:
        timestring = "\n CREATED: not_available MODIFIED: not_available ACCESSED: not_available"
    return timestring


def runProcess(command, timeout=10, logger=None):
    """
    Run a process and check it's output
    :param command: command to run (list or string)
    :param timeout: timeout in seconds
    :param logger: optional logger instance for error logging
    :return: tuple of (output, returnCode)
    """
    output = ""
    returnCode = 0

    # Kill check
    try:
        kill_check = threading.Event()

        def _kill_process_after_a_timeout(pid):
            try:
                os.kill(pid, signal.SIGTERM)
                kill_check.set()  # tell the main routine that we had to kill
                timeout_msg = f"timeout hit - killing pid {pid}"
                print(timeout_msg)
                if logger:
                    logger.log("WARNING", "Helpers", timeout_msg)
            except Exception as e:
                if logger:
                    logger.log("DEBUG", "Helpers", f"Error killing process {pid}: {str(e)}")
            return "", 1

        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            returnCode = e.returncode
            if logger:
                logger.log("DEBUG", "Helpers", f"Process call error: {str(e)}")
            return "", returnCode
        except Exception as e:
            error_msg = f"Error starting process: {str(e)}"
            if logger:
                logger.log("WARNING", "Helpers", error_msg)
            return error_msg, 1
        
        pid = p.pid
        watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid,))
        watchdog.start()
        try:
            (stdout, stderr) = p.communicate()
            output = "{0}{1}".format(stdout.decode('utf-8', errors='replace'), 
                                    stderr.decode('utf-8', errors='replace'))
            returnCode = p.returncode
            if returnCode != 0 and logger:
                logger.log("DEBUG", "Helpers", f"Process {pid} exited with code {returnCode}")
        finally:
            watchdog.cancel()  # if it's still waiting to run
            success = not kill_check.isSet()
            kill_check.clear()
    except Exception as e:
        if logger:
            logger.log("WARNING", "Helpers", f"Error in runProcess: {str(e)}")
        pass

    return output, returnCode


def getHostname(os_platform):
    """
    Generate and return a hostname
    :return: hostname string
    """
    try:
        # Computername
        if os_platform == "linux" or os_platform == "macos":
            return os.uname()[1]
        else:
            return os.environ.get('COMPUTERNAME', 'unknown')
    except Exception:
        return "unknown"


def getLocalIP():
    """
    Get the local IP address of the machine
    :return: IP address as string
    """
    try:
        # Connect to a remote address to determine local IP
        # Using a non-routable address to avoid actual network traffic
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't actually connect, just determines local IP
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            # Fallback: try to get hostname and resolve it
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                ip = "unknown"
        finally:
            try:
                s.close()
            except Exception:
                pass
        return ip
    except Exception:
        # If all else fails, return a default
        return "unknown"
