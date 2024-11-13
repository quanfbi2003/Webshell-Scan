#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import os
import platform
import re
import shutil
import sys
import traceback
import zipfile
import yara
import urllib.request

# Đổi hàm `urlopen` sang Python 3
urlopen = urllib.request.urlopen

try:
    import win32api
except ImportError:
    pass

from libs.logger import *

# Platform
_platform = sys.platform
platform = ""
if _platform == "win32":
    platform = "windows"
elif _platform in ("linux", "linux2"):
    platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

dummy = ""

def check_yara_rule(rule_text, new_rule):
    try:
        yara.compile(source=rule_text, externals={
            'filename': dummy,
            'filepath': dummy,
            'extension': dummy,
            'filetype': dummy,
            'md5': dummy,
            'owner': dummy,
        })
        return True
    except Exception as e:
        print("Syntax error in rule: {0}".format(e))
        if "undefined identifier" in str(e):
            print(new_rule)
        return False

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

class Updater(object):
    # Incompatible signatures
    INCOMPATIBLE_RULES = ["Ransomeware", "Ransom"]

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip",
        "https://github.com/DarkenCode/yara-rules/archive/refs/heads/master.zip",
        "https://github.com/nsacyber/Mitigating-Web-Shells/archive/refs/heads/master.zip",
        "https://github.com/Sprite-Pop/Webshell_yara/archive/refs/heads/main.zip",
        "https://github.com/farhanfaisal/yararule_web/archive/refs/heads/master.zip"
    ]

    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path

    def update_signatures(self):
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                try:
                    self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                    response = urlopen(sig_url)
                except Exception:
                    traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error downloading the signature database - "
                                                         "check your Internet connection")
                    sys.exit(1)

                # Read ZIP file
                try:
                    sigDir = os.path.join(self.application_path, os.path.abspath('libs/signature-base/'.replace("/", os.sep)))
                    zipUpdate = zipfile.ZipFile(io.BytesIO(response.read()))
                    for zipFilePath in zipUpdate.namelist():
                        sigName = os.path.basename(zipFilePath)
                        if zipFilePath.endswith("/".replace("/", os.sep)):
                            continue
                        # Skip incompatible rules
                        skip = False
                        for incompatible_rule in self.INCOMPATIBLE_RULES:
                            if sigName.endswith(incompatible_rule) or str(incompatible_rule).lower() in str(
                                    sigName).lower():
                                self.logger.log("NOTICE", "Upgrader", "Skipping incompatible rule %s" % sigName)
                                skip = True
                        if skip:
                            continue
                        # Extract the rules
                        self.logger.log("DEBUG", "Upgrader", "Extracting %s ..." % zipFilePath)
                        if "/iocs/" in zipFilePath and zipFilePath.endswith(".txt"):
                            targetFile = os.path.join(sigDir, "iocs", sigName)
                        elif "/yara/" in zipFilePath and zipFilePath.endswith(".yar"):
                            targetFile = os.path.join(sigDir, "yara", sigName)
                        elif "/misc/" in zipFilePath and zipFilePath.endswith(".txt"):
                            targetFile = os.path.join(sigDir, "misc", sigName)
                        elif zipFilePath.endswith(".yara"):
                            targetFile = os.path.join(sigDir, "yara", sigName)
                        else:
                            continue

                        # New file
                        if not os.path.exists(targetFile):
                            self.logger.log("INFO", "Upgrader", "New signature file: %s" % sigName)

                        # Extract file
                        dir_name = os.path.dirname(targetFile)
                        if not os.path.exists(dir_name):
                            os.makedirs(dir_name)
                        source = zipUpdate.open(zipFilePath)
                        target = open(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)

                except Exception:
                    traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error while extracting the signature files from the download "
                                                         "package")
                    sys.exit(1)
            self.combine_yara_rules()
        except Exception:
            traceback.print_exc()
            return False
        return True

    def combine_yara_rules(self):
        sigDir = os.path.join(self.application_path, os.path.abspath('libs/signature-base/yara/'.replace("/", os.sep)))
        yara_imports = ""
        yara_rules = ""
        org_rules = ""
        for root, dirs, files in os.walk(sigDir):
            for file in files:
                file_path = os.path.join(root, file)
                self.logger.log("INFO", "Upgrader", "Processing file: {}".format(file_path))
                with open(file_path, 'r') as f:
                    rules = f.read()
                    org_rules += f"{rules}\n"
                    imports = re.findall(r'import\s+".+?"$', rules, re.MULTILINE)
                    for imp in imports:
                        if imp not in yara_imports and check_yara_rule(imp, imp):
                            yara_imports += imp + "\n"
                    yara_rule = re.findall(r'rule\s.*?{.*?condition:.*?}', rules, re.DOTALL)
                    for rule in yara_rule:
                        separate = separate_rule(rule)
                        for ru in separate:
                            temp_combined = yara_rules + ru + "\n"
                            if check_yara_rule(yara_imports + temp_combined, ru):
                                yara_rules = temp_combined
        self.clean_dir("yara/".replace("/", os.sep))
        with open(sigDir + "/webshell_scan.yar".replace("/", os.sep), 'w') as f:
            f.write(yara_imports + yara_rules)
        with open(sigDir + "/webshell_scan_org.yar".replace("/", os.sep), 'w') as f:
            f.write(org_rules)
            self.logger.log("INFO", "Upgrader", "Valid YARA rules saved to " + sigDir + "/webshell_scan.yar".replace("/", os.sep))

    def clean_dir(self, target):
        try:
            sigDir = os.path.join(self.application_path, os.path.abspath('libs/signature-base/'.replace("/", os.sep)))
            fullOutDir = os.path.join(sigDir, target)
            shutil.rmtree(fullOutDir)
            self.logger.log("INFO", "Upgrader", "Cleaning directory '%s'" % fullOutDir)
            if not os.path.exists(fullOutDir):
                os.makedirs(fullOutDir)
        except Exception:
            traceback.print_exc()
            self.logger.log("ERROR", "Upgrader", "Error while creating the signature-base directories")
            sys.exit(1)

def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and platform == "windows":
            application_path = win32api.GetLongPathName(application_path)
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        traceback.print_exc()

if __name__ == '__main__':
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    logger = Logger(t_hostname, platform=platform, caller='upgrader')

    updater = Updater(False, logger, get_application_path())
    logger.log("INFO", "Upgrader", "Updating Signatures ...")

    updater.update_signatures()

    logger.log("INFO", "Upgrader", "Update complete")

    sys.exit(0)
