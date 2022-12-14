import io
import shutil
import zipfile
from sys import platform as _platform
from urllib.request import urlopen
import win32api

from libs.logger import *

# Platform
platform = ""
if _platform == "win32":
    platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")


class Updater(object):
    # Incompatible signatures
    INCOMPATIBLE_RULES = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]

    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path

    def update_signatures(self, clean=False):
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                # Downloading current repository
                try:
                    self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                    response = urlopen(sig_url)
                except Exception as e:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error downloading the signature database - "
                                                         "check your Internet connection")
                    sys.exit(1)

                # Preparations
                try:
                    sigDir = os.path.join(self.application_path, os.path.abspath('libs/signature-base/'))
                    if clean:
                        self.logger.log("INFO", "Upgrader", "Cleaning directory '%s'" % sigDir)
                        shutil.rmtree(sigDir)
                    for outDir in ['', 'iocs', 'yara', 'misc']:
                        fullOutDir = os.path.join(sigDir, outDir)
                        if not os.path.exists(fullOutDir):
                            os.makedirs(fullOutDir)
                except Exception as e:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error while creating the signature-base directories")
                    sys.exit(1)

                # Read ZIP file
                try:
                    zipUpdate = zipfile.ZipFile(io.BytesIO(response.read()))
                    for zipFilePath in zipUpdate.namelist():
                        sigName = os.path.basename(zipFilePath)
                        if zipFilePath.endswith("/"):
                            continue
                        # Skip incompatible rules
                        skip = False
                        for incompatible_rule in self.INCOMPATIBLE_RULES:
                            if sigName.endswith(incompatible_rule):
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
                        source = zipUpdate.open(zipFilePath)
                        target = open(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                        target.close()
                        source.close()

                except Exception as e:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error while extracting the signature files from the download "
                                                         "package")
                    sys.exit(1)

        except Exception as e:
            if self.debug:
                traceback.print_exc()
            return False
        return True


def get_application_path():
    try:
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        if "~" in application_path and platform == "windows":
            # print "Trying to translate"
            # print application_path
            application_path = win32api.GetLongPathName(application_path)
        # if args.debug:
        #    logger.log("DEBUG", "Init", "Application Path: %s" % application_path)
        return application_path
    except Exception as e:
        print("Error while evaluation of application path")
        traceback.print_exc()


if __name__ == '__main__':
    # Computername
    import os
    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    # Logger
    logger = Logger(t_hostname, platform=platform, caller='upgrader')

    # Update
    updater = Updater(False, logger, get_application_path())

    logger.log("INFO", "Upgrader", "Updating Signatures ...")

    updater.update_signatures(False)

    logger.log("INFO", "Upgrader", "Update complete")

    sys.exit(0)
