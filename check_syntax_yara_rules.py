import os

import yara

# Đường dẫn đến thư mục chứa các tệp YARA rules
yara_folder = "libs/signature-base/yara"
dummy = ""


def is_valid_yara_rule(rule_text):
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


# Duyệt qua tất cả các tệp YARA rules trong thư mục YARA
for root, dirs, files in os.walk(yara_folder):
    for file_name in files:
        if file_name.endswith(".yar") or file_name.endswith(".yara"):
            file_path = os.path.join(root, file_name)

            # Đọc nội dung từ tệp YARA
            with open(file_path, "r") as yara_file:
                yara_content = yara_file.read()

            # Kiểm tra xem rule có lỗi cú pháp hay không
            if not is_valid_yara_rule(yara_content):
                print(f"Rule in {file_name} has syntax errors.")
