import os

# Đường dẫn đến thư mục chứa các tệp YARA rules
yara_dir = 'libs/signature-base/yara'

# Lấy danh sách các tệp trong thư mục
files = os.listdir(yara_dir)

# Tạo một từ điển để lưu trữ số lần xuất hiện của mỗi tên luật
rule_names = {}

# Duyệt qua từng tệp YARA rules trong thư mục
for file in files:
    if True:
        with open(os.path.join(yara_dir, file), 'r') as f:
            content = f.read()
            # Tìm tên luật trong tệp
            for line in content.split('\n'):
                if line.strip().startswith('rule '):
                    rule_name = line.strip()[5:].split('(')[0].strip().split("/s+")[0]
                    # Kiểm tra xem tên luật đã xuất hiện trước đó chưa
                    if rule_name in rule_names:
                        # Đổi tên luật nếu đã tồn tại
                        new_rule_name = rule_name + '_new'
                        content = content.replace(f'rule {rule_name}', f'rule {new_rule_name}')
                        # Cập nhật từ điển
                        rule_names[new_rule_name] = 1
                    else:
                        rule_names[rule_name] = 1
        # Lưu lại nội dung tệp sau khi đã đổi tên
        with open(os.path.join(yara_dir, file), 'w') as f:
            f.write(content)
