import io
import shutil
import zipfile
from sys import platform as _platform
from urllib.request import urlopen

try:
    import win32api
except:
    pass
import yara

from libs.logger import *

# Platform
platform = ""
if _platform == "win32":
    platform = "windows"
elif _platform == "linux" or _platform == "linux2":
    platform = "linux"
else:
    sys.exit("This script is only for Windows and Linux.")

dummy = ""


def check_yara_rule(rule_text):
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
    except yara.SyntaxError as e:
        print(f"Syntax error in rule: {e}")
        return False


def is_valid_yara_rule(rule_text):
    yara_imports = "\n".join(re.findall(r'import\s+".+?"$', rule_text, re.MULTILINE))
    yara_rules = re.split(r'#########split#########', rule_text.replace(r'import\s+".+?"$', ""))[1:]
    addition_part = re.split(r'#########split#########', rule_text.replace(r'import\s+".+?"$', ""))[0]
    cut_index = addition_part.rfind('}')
    res = ""
    for rule in yara_rules:
        # Tìm vị trí cuối cùng của dấu '}'
        end_brace_index = rule.rfind('}')

        # Loại bỏ các ký tự cuối cùng
        fixed_rule = rule[:end_brace_index + 1]
        if check_yara_rule(f"{yara_imports}\n{addition_part}\n{res}\n{fixed_rule}"):
            res += fixed_rule + "\n"
    return f"{yara_imports}\n{res}" if res != "" else ""


class Updater(object):
    # Incompatible signatures
    INCOMPATIBLE_RULES = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip",
        "https://github.com/DarkenCode/yara-rules/archive/refs/heads/master.zip",
        "https://github.com/nsacyber/Mitigating-Web-Shells/archive/refs/heads/master.zip"
    ]

    def __init__(self, debug, logger, application_path):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path

    def update_signatures(self, clean=False):
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                sig_author = sig_url.split('/')[3]
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
                        elif zipFilePath.endswith(".yar"):
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
                        if zipFilePath.endswith(".yara") or zipFilePath.endswith(".yar"):
                            with open(targetFile, 'r') as f:
                                content = f.read()
                                # Tìm tên luật trong tệp
                                for line in content.split('\n'):
                                    if line.strip().startswith('rule '):
                                        rule_name = line.strip()[5:].split('(')[0].strip()
                                        content = content.replace(f'rule {rule_name}',
                                                                  f'#########split#########\nrule {sig_author.replace(" ", "")}_{sigName[:3]}_{rule_name}')

                            # Lưu lại nội dung tệp sau khi đã đổi tên
                            with open(targetFile, 'w') as f:
                                res = is_valid_yara_rule(content)
                                while not check_yara_rule(res):
                                    res = is_valid_yara_rule(res)
                                f.write(res)

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
