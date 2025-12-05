# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import hashlib
import io
import os
import re
import shutil
import sys
import traceback
import zipfile
from sys import platform as _platform
from urllib.request import urlopen
from datetime import datetime as dt

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


def mark_commented_lines(content):
    """
    Đánh dấu các dòng/đoạn bị comment trong file
    Trả về một dict với:
    - 'block_comments': set các chỉ số dòng nằm trong comment block /* ... */
    - 'line_comments': dict {line_num: comment_pos} - vị trí của // trong mỗi dòng
    
    Xử lý:
    - Comment line (//): lưu vị trí của // để kiểm tra rule có nằm sau // không
    - Comment block (/* ... */): đánh dấu tất cả các dòng trong block
    """
    lines = content.split('\n')
    block_commented_lines = set()
    line_comments = {}  # {line_num: comment_pos}
    
    # Đánh dấu các dòng trong comment block
    in_block_comment = False
    block_start_line = -1
    
    for line_num, line in enumerate(lines):
        # Xử lý comment block /* ... */
        pos = 0
        while pos < len(line):
            if not in_block_comment:
                # Tìm /* để bắt đầu block comment
                open_pos = line.find('/*', pos)
                if open_pos >= 0:
                    # Kiểm tra xem /* có nằm trong string không
                    before_open = line[:open_pos]
                    quote_count = 0
                    i = 0
                    while i < len(before_open):
                        if before_open[i] == '\\':
                            i += 2
                            continue
                        elif before_open[i] == '"':
                            quote_count += 1
                        i += 1
                    
                    # Nếu số dấu " là chẵn, /* không nằm trong string
                    if quote_count % 2 == 0:
                        in_block_comment = True
                        block_start_line = line_num
                        # Tìm */ trong cùng dòng (sau /*)
                        # Cần kiểm tra xem */ có nằm trong string không
                        search_pos = open_pos + 2
                        close_pos = line.find('*/', search_pos)
                        while close_pos >= 0:
                            # Kiểm tra xem */ có nằm trong string không
                            before_close = line[:close_pos]
                            quote_count_close = 0
                            j = 0
                            while j < len(before_close):
                                if before_close[j] == '\\':
                                    j += 2
                                    continue
                                elif before_close[j] == '"':
                                    quote_count_close += 1
                                j += 1
                            
                            # Nếu số dấu " là chẵn, */ không nằm trong string
                            if quote_count_close % 2 == 0:
                                # Block comment kết thúc trong cùng dòng (comment inline)
                                # KHÔNG đánh dấu dòng này vì đây là comment inline, không ảnh hưởng đến rule
                                in_block_comment = False
                                pos = close_pos + 2
                                break
                            else:
                                # */ nằm trong string, tìm tiếp
                                close_pos = line.find('*/', close_pos + 2)
                        
                        if in_block_comment:
                            # Block comment tiếp tục ở dòng sau
                            block_commented_lines.add(line_num)
                            pos = len(line)
                        continue
                    else:
                        # /* nằm trong string, bỏ qua
                        pos = open_pos + 2
                else:
                    break
            else:
                # Đang trong block comment, tìm */ để kết thúc
                # Cần kiểm tra xem */ có nằm trong string không
                close_pos = line.find('*/', pos)
                while close_pos >= 0:
                    # Kiểm tra xem */ có nằm trong string không
                    before_close = line[:close_pos]
                    quote_count = 0
                    j = 0
                    while j < len(before_close):
                        if before_close[j] == '\\':
                            j += 2
                            continue
                        elif before_close[j] == '"':
                            quote_count += 1
                        j += 1
                    
                    # Nếu số dấu " là chẵn, */ không nằm trong string
                    if quote_count % 2 == 0:
                        # Đánh dấu tất cả các dòng từ block_start_line đến line_num
                        for i in range(block_start_line, line_num + 1):
                            block_commented_lines.add(i)
                        in_block_comment = False
                        block_start_line = -1
                        pos = close_pos + 2
                        break
                    else:
                        # */ nằm trong string, tìm tiếp
                        close_pos = line.find('*/', close_pos + 2)
                
                if in_block_comment:
                    # Block comment tiếp tục
                    block_commented_lines.add(line_num)
                    pos = len(line)
        
        # Xử lý comment line (//)
        if not in_block_comment:
            comment_pos = line.find('//')
            if comment_pos >= 0:
                # Kiểm tra xem // có nằm trong string không
                before_comment = line[:comment_pos]
                quote_count = 0
                i = 0
                while i < len(before_comment):
                    if before_comment[i] == '\\':
                        i += 2
                        continue
                    elif before_comment[i] == '"':
                        quote_count += 1
                    i += 1
                
                # Nếu số dấu " là chẵn, // không nằm trong string
                if quote_count % 2 == 0:
                    # Lưu vị trí của // để kiểm tra rule có nằm sau // không
                    line_comments[line_num] = comment_pos
    
    # Nếu vẫn còn block comment mở (không đóng), đánh dấu tất cả các dòng từ block_start_line đến cuối
    if in_block_comment:
        for i in range(block_start_line, len(lines)):
            block_commented_lines.add(i)
    
    return {'block_comments': block_commented_lines, 'line_comments': line_comments}


def is_rule_commented(line_num, line, commented_info):
    """
    Kiểm tra xem rule có bị comment không dựa trên thông tin đã đánh dấu
    
    Args:
        line_num: chỉ số dòng
        line: nội dung dòng
        commented_info: dict từ mark_commented_lines với 'block_comments' và 'line_comments'
    
    Returns:
        True nếu rule bị comment, False nếu không
    """
    # Kiểm tra block comment
    if line_num in commented_info['block_comments']:
        return True
    
    # Kiểm tra line comment (//)
    if line_num in commented_info['line_comments']:
        comment_pos = commented_info['line_comments'][line_num]
        # Tìm vị trí của từ 'rule' trong dòng
        rule_match = re.search(r'\brule\b', line)
        if rule_match:
            rule_pos = rule_match.start()
            # Nếu rule nằm sau //, rule bị comment
            if rule_pos > comment_pos:
                return True
    
    return False


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
        return True, None
    except Exception as exp:
        return False, str(exp)


def yara_rule_match(rule_text, test_file_path=None):
    """
    Test YARA rule bằng cách compile và match với file thực tế
    
    Args:
        rule_text: Nội dung rule cần test
        test_file_path: Đường dẫn file test (nếu None, tạo file test tạm thời)
    
    Returns:
        (is_valid, error_msg, matches_count)
        - is_valid: True nếu compile và match thành công
        - error_msg: Thông báo lỗi nếu có
        - matches_count: Số lượng match (0 nếu không match, >0 nếu có match)
    """
    import tempfile
    import os
    
    try:
        # Compile rule
        rules = yara.compile(source=rule_text, externals={
            'filename': dummy,
            'filepath': dummy,
            'extension': dummy,
            'filetype': dummy,
            'md5': dummy,
            'owner': dummy,
        })
        
        # Tạo file test nếu chưa có
        if test_file_path is None:
            # Tạo file test PHP đơn giản (webshell sample)
            test_content = b"<?php eval($_GET['cmd']); ?>"
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.php', delete=False) as f:
                f.write(test_content)
                test_file_path = f.name
        
        # Test match với file
        if os.path.exists(test_file_path):
            matches = rules.match(test_file_path)
            matches_count = len(matches)
        else:
            # Nếu file không tồn tại, chỉ test compile (không test match)
            matches_count = 0
        
        # Xóa file test tạm thời nếu đã tạo
        if test_file_path and os.path.exists(test_file_path) and test_file_path.startswith(tempfile.gettempdir()):
            try:
                os.remove(test_file_path)
            except:
                pass
        
        return True, None, matches_count
    except yara.SyntaxError as exp:
        return False, f"Compilation error: {str(exp)}", 0
    except yara.Error as exp:
        return False, f"YARA error: {str(exp)}", 0
    except Exception as exp:
        return False, f"Unexpected error: {str(exp)}", 0


def extract_rule_name(rule_text):
    """Trích xuất tên rule từ rule text"""
    match = re.search(r'^\s*(?:private\s+|global\s+)*rule\s+([^\s:{(]+)', rule_text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def has_inline_comment(rule_text):
    """
    Kiểm tra xem rule có chứa comment block /* ... */ (có thể inline hoặc nhiều dòng) không
    
    Args:
        rule_text: Nội dung rule cần kiểm tra
    
    Returns:
        True nếu có comment block, False nếu không
    """
    if not rule_text.strip():
        return False
    
    lines = rule_text.split('\n')
    in_comment = False  # Trạng thái đang trong block comment
    
    for line in lines:
        i = 0
        quote_count = 0  # Đếm số dấu " (không tính escaped)
        
        while i < len(line):
            # Bỏ qua escaped characters
            if i < len(line) - 1 and line[i] == '\\':
                i += 2
                continue
            
            # Đếm dấu " để biết có đang trong string không
            if line[i] == '"':
                quote_count += 1
            
            # Chỉ xử lý comment khi không nằm trong string (số dấu " là chẵn)
            if quote_count % 2 == 0:
                # Kiểm tra /* (bắt đầu comment block)
                if i < len(line) - 1 and line[i:i+2] == '/*':
                    in_comment = True
                    i += 2
                    continue
                
                # Kiểm tra */ (kết thúc comment block)
                if i < len(line) - 1 and line[i:i+2] == '*/':
                    if in_comment:
                        # Tìm thấy comment block (có thể inline hoặc multi-line)
                        return True
                    i += 2
                    continue
            
            i += 1
    
    return False


def comment_rule_with_slash(rule_text):
    """
    Comment toàn bộ rule bằng cách thêm // vào đầu mỗi dòng
    
    Args:
        rule_text: Nội dung rule cần comment
    
    Returns:
        Rule đã được comment bằng // ở đầu mỗi dòng
    """
    if not rule_text.strip():
        return rule_text
    
    lines = rule_text.split('\n')
    commented_lines = []
    for line in lines:
        if line.strip():  # Chỉ comment dòng không rỗng
            commented_lines.append('//' + line)
        else:  # Giữ nguyên dòng rỗng
            commented_lines.append(line)
    
    return '\n'.join(commented_lines)


def comment_rule(rule_text):
    """
    Comment toàn bộ rule với cơ chế nhiều bước an toàn:
    1. Thử comment bằng /* ... */ bao quanh toàn bộ rule
    2. Nếu vẫn lỗi → thử comment từng dòng bằng /* ... */
    3. Nếu vẫn lỗi → lặp:
       - Dựa vào thông báo lỗi để tìm dòng lỗi
       - Thay riêng dòng lỗi đó bằng //line, compile lại
       - Nếu vẫn lỗi ở đúng dòng đó → thay dòng đó bằng /*DELETED*/
    
    Args:
        rule_text: Nội dung rule cần comment
    
    Returns:
        Rule đã được comment (giữ nguyên số dòng), ưu tiên giữ nguyên nội dung tối đa có thể
    """
    if not rule_text.strip():
        return rule_text
    
    # Helper compile
    def _compile_ok(text: str):
        res, _ = check_yara_rule(text)
        return res

    # Bước 1: Thử comment bằng /* ... */ bao quanh toàn bộ rule
    commented_block = f"/*\n{rule_text}\n*/"
    if _compile_ok(commented_block):
        return commented_block

    # Chuẩn bị danh sách dòng gốc
    original_lines = rule_text.split('\n')

    # Bước 2: Thử comment từng dòng bằng /* ... */
    line_commented = []
    for line in original_lines:
        if line.strip():
            # Giữ indent, bọc nội dung dòng trong /* ... */
            leading_ws_len = len(line) - len(line.lstrip(' '))
            leading_ws = line[:leading_ws_len]
            content_part = line[leading_ws_len:]
            line_commented.append(f"{leading_ws}/*{content_part}*/")
        else:
            line_commented.append(line)

    current_lines = line_commented
    current_text = '\n'.join(current_lines)

    if _compile_ok(current_text):
        return current_text

    # Bước 3: Lặp – dựa vào thông báo lỗi để xử lý từng dòng
    # Mục tiêu: không bao giờ thay đổi số lượng dòng, chỉ thay nội dung từng dòng
    max_iterations = len(current_lines) * 2  # giới hạn an toàn
    for _ in range(max_iterations):
        is_ok, error_msg = check_yara_rule(current_text)
        if is_ok:
            return current_text

        # Cố gắng lấy số dòng lỗi từ thông báo YARA: "line N: ..."
        error_line_idx = None
        if error_msg:
            m = re.search(r'line\s+(\d+)', error_msg)
            if m:
                line_no = int(m.group(1))
                if 1 <= line_no <= len(current_lines):
                    error_line_idx = line_no - 1

        # Nếu không xác định được dòng lỗi, fallback: dùng comment_rule_with_slash toàn rule
        if error_line_idx is None:
            commented_slash_all = comment_rule_with_slash(rule_text)
            if _compile_ok(commented_slash_all):
                return commented_slash_all
            # Nếu vẫn lỗi, thay toàn bộ rule bằng /*DELETED*/
            return "/*DELETED*/"

        # Xử lý dòng lỗi cụ thể
        orig_line = original_lines[error_line_idx]
        cur_line = current_lines[error_line_idx]

        # Giữ indent gốc
        leading_ws_len = len(orig_line) - len(orig_line.lstrip(' '))
        leading_ws = orig_line[:leading_ws_len]
        content_part = orig_line[leading_ws_len:]

        # Nếu dòng hiện tại đã là //... → bước tiếp theo là /*DELETED*/
        stripped_cur = cur_line.lstrip()
        if stripped_cur.startswith('//'):
            current_lines[error_line_idx] = f"{leading_ws}/*DELETED*/"
        else:
            # Thử đổi dòng lỗi sang //line
            current_lines[error_line_idx] = f"{leading_ws}//{content_part}"

        current_text = '\n'.join(current_lines)

    # Nếu vượt quá số vòng lặp an toàn mà vẫn lỗi, cuối cùng thay toàn bộ rule bằng /*DELETED*/
    return "/*DELETED*/"


def analyze_and_filter_rules_simple(rule_text, accumulated_rules="", logger=None, debug_log=None):
    """
    Phiên bản đơn giản: Chỉ cắt rule và check compile OK theo thứ tự trong file
    Rule lỗi sẽ được comment lại thay vì xóa, và thêm tag ===FAILED===
    Rule thành công sẽ thêm tag ===SUCCESS===
    
    Args:
        rule_text: Nội dung file chứa các rule
        accumulated_rules: Các rule đã tích lũy từ các file trước
        logger: Logger để ghi log
        debug_log: Hàm để ghi log chi tiết debug (optional)
    
    Returns:
        (accepted_rules, failed_rules, total_count, valid_count, accumulated_rules)
        - accepted_rules: Tất cả rules (thành công có tag ===SUCCESS===, lỗi có tag ===FAILED=== và đã comment)
        - failed_rules: Danh sách rules lỗi
        - total_count: Tổng số rules
        - valid_count: Số rules compile được
        - accumulated_rules: Các rule đã tích lũy (chỉ rule thành công, không comment)
    """
    # Tách imports và phần còn lại
    yara_imports = "\n".join(re.findall(r'import\s+".+?"', rule_text, re.MULTILINE))
    
    # Loại bỏ imports khỏi rule_text để tách rules
    rule_text_no_imports = re.sub(r'import\s+".+?"\s*\n?', '', rule_text, flags=re.MULTILINE)
    
    # Tách rules bằng marker
    parts = re.split(r'//#########split#########', rule_text_no_imports)
    addition_part = parts[0] if parts else ""
    yara_rules = parts[1:] if len(parts) > 1 else []
    
    # Loại bỏ các rule rỗng
    yara_rules = [rule for rule in yara_rules if rule.strip()]
    
    if not yara_rules:
        return "", [], 0, 0, accumulated_rules
    
    # Khởi tạo accepted_rules với imports và addition_part
    accepted_rules = ""
    if yara_imports:
        accepted_rules += yara_imports + "\n"
    if addition_part.strip():
        accepted_rules += addition_part + "\n"
    
    # Khởi tạo accumulated_rules nếu rỗng
    if not accumulated_rules.strip():
        if yara_imports:
            accumulated_rules = yara_imports + "\n"
        if addition_part.strip():
            accumulated_rules += addition_part + "\n"
    
    failed_rules = []
    valid_count = 0
    total_count = len(yara_rules)
    
    # Track tên các rule đã failed để kiểm tra rule sau có reference đến không
    failed_rule_names = set()
    
    if debug_log:
        debug_log(f"Processing {total_count} rule(s) in file order (simple mode - no relevance filter)...", 2)
    
    # Xử lý từng rule theo thứ tự trong file
    for idx, rule in enumerate(yara_rules, 1):
        rule_text = rule.strip()
        if not rule_text:
            continue
        
        end_brace_index = rule_text.rfind('}')
        if end_brace_index < 0:
            error_msg = f"Rule #{idx}: Missing closing brace"
            failed_rules.append(("", error_msg))
            if debug_log:
                debug_log(f"Rule #{idx}: INCOMPLETE (missing closing brace)", 3)
            
            # Comment rule lỗi và thêm vào accepted_rules với tag ===FAILED===
            commented_rule = comment_rule(rule_text)
            if commented_rule is not None:
                accepted_rules += f"//===FAILED===\n{commented_rule}\n"
            # Nếu commented_rule là None, rule không thể comment (cả hai cách đều lỗi), bỏ qua (xóa rule)
            continue
        
        fixed_rule_text = rule_text[:end_brace_index+1]
        current_rule_name = extract_rule_name(fixed_rule_text)
        
        if not current_rule_name:
            error_msg = f"Rule #{idx}: Cannot extract rule name"
            failed_rules.append(("", error_msg))
            if debug_log:
                debug_log(f"Rule #{idx}: INVALID (cannot extract rule name)", 3)
            
            # Comment rule lỗi và thêm vào accepted_rules với tag ===FAILED===
            commented_rule = comment_rule(fixed_rule_text)
            if commented_rule is not None:
                accepted_rules += f"//===FAILED===\n{commented_rule}\n"
            # Nếu commented_rule là None, rule không thể comment (cả hai cách đều lỗi), bỏ qua (xóa rule)
            continue
        
        if debug_log:
            debug_log(f"Rule #{idx}/{total_count}: '{current_rule_name}'", 3)
        
        # Kiểm tra xem rule có chứa tên rule đã failed không
        # Duyệt rule failed, nếu tên rule nào in trong rule hiện tại thì tồn tại
        references_failed_rule = False
        referenced_failed_rules = []
        for failed_rule_name in failed_rule_names:
            if failed_rule_name in fixed_rule_text:
                references_failed_rule = True
                referenced_failed_rules.append(failed_rule_name)
        
        if references_failed_rule:
            # Rule chứa tên rule đã failed -> rule này cũng sẽ compile lỗi
            error_msg = f"Rule contains failed rule name(s): {', '.join(referenced_failed_rules)}"
            failed_rule_names.add(current_rule_name)
            failed_rules.append((current_rule_name, error_msg))
            if debug_log:
                debug_log(f"  Result: FAILED (contains failed rule name(s): {', '.join(referenced_failed_rules)})", 4)
                # Đảm bảo log chi tiết cũng ghi vào file log chung
                debug_log(f"Rule '{current_rule_name}' contains failed rule name(s): {', '.join(referenced_failed_rules)}", 4)
            if logger:
                # WARNING này đã được ghi chi tiết vào file log qua debug_log ở trên
                logger.log("WARNING", "Upgrader", f"Rule '{current_rule_name}' contains failed rule name(s): {', '.join(referenced_failed_rules)}")
            
            # Comment rule lỗi và thêm vào accepted_rules với tag ===FAILED===
            commented_rule = comment_rule(fixed_rule_text)
            if commented_rule is not None:
                accepted_rules += f"//===FAILED===\n{commented_rule}\n"
            # Nếu commented_rule là None, rule không thể comment (cả hai cách đều lỗi), bỏ qua (xóa rule)
            continue
        
        # Kiểm tra compile với accumulated_rules
        test_with_accumulated = accumulated_rules + fixed_rule_text + "\n"
        is_valid, error_msg = check_yara_rule(test_with_accumulated)
        
        if not is_valid:
            # Rule compile lỗi
            failed_rule_names.add(current_rule_name)
            failed_rules.append((current_rule_name, f"Compilation error: {error_msg}"))
            if debug_log:
                debug_log(f"  Result: FAILED (compile error: {error_msg})", 4)
                # Ghi thêm log chi tiết vào file log chung
                debug_log(f"Rule '{current_rule_name}' compilation error: {error_msg}", 4)
            if logger:
                # WARNING này cũng đã được ghi chi tiết vào file log qua debug_log
                logger.log("WARNING", "Upgrader", f"Rule '{current_rule_name}' compilation error: {error_msg}")
            
            # Comment rule lỗi và thêm vào accepted_rules với tag ===FAILED===
            commented_rule = comment_rule(fixed_rule_text)
            if commented_rule is not None:
                accepted_rules += f"//===FAILED===\n{commented_rule}\n"
            # Nếu commented_rule là None, rule không thể comment (cả hai cách đều lỗi), bỏ qua (xóa rule)
            continue
        
        # Rule compile được, test match với file webshell mẫu
        is_match_valid, match_error_msg, matches_count = yara_rule_match(test_with_accumulated)
        
        if not is_match_valid:
            # Rule match test lỗi
            failed_rule_names.add(current_rule_name)
            failed_rules.append((current_rule_name, f"Match test error: {match_error_msg}"))
            if debug_log:
                debug_log(f"  Result: FAILED (match test error: {match_error_msg})", 4)
                # Ghi thêm log chi tiết vào file log chung
                debug_log(f"Rule '{current_rule_name}' match test error: {match_error_msg}", 4)
            if logger:
                # WARNING này cũng đã được ghi chi tiết vào file log qua debug_log
                logger.log("WARNING", "Upgrader", f"Rule '{current_rule_name}' match test error: {match_error_msg}")
            
            # Comment rule lỗi và thêm vào accepted_rules với tag ===FAILED===
            commented_rule = comment_rule(fixed_rule_text)
            if commented_rule is not None:
                accepted_rules += f"//===FAILED===\n{commented_rule}\n"
            # Nếu commented_rule là None, rule không thể comment (cả hai cách đều lỗi), bỏ qua (xóa rule)
            continue
        
        # Rule compile được và match test thành công, thêm vào accepted_rules và accumulated_rules
        # Thêm tag ===SUCCESS=== trước rule thành công
        accepted_rules += f"//===SUCCESS===\n{fixed_rule_text}\n"
        accumulated_rules += fixed_rule_text + "\n"
        valid_count += 1
        
        if debug_log:
            debug_log(f"  Result: SUCCESS (compiles with accumulated_rules and match test passed, matches: {matches_count})", 4)
            # Ghi thêm log chi tiết vào file log chung
            debug_log(f"Rule '{current_rule_name}' compiled successfully and match test passed (matches: {matches_count})", 4)
        if logger:
            logger.log("INFO", "Upgrader", f"Rule '{current_rule_name}' compiled successfully and match test passed")
    
    # Loại bỏ dòng trống cuối cùng
    accepted_rules = accepted_rules.rstrip()
    accumulated_rules = accumulated_rules.rstrip()
    
    if debug_log:
        debug_log(f"Simple processing complete: {valid_count}/{total_count} rule(s) compiled successfully", 2)

    return accepted_rules, failed_rules, total_count, valid_count, accumulated_rules


class Updater(object):
    # Blacklist tên file (hỗ trợ wildcard pattern như abc*, *.yar, test_*)
    # Các file có tên khớp với pattern trong danh sách này sẽ bị bỏ qua hoàn toàn
    FILE_NAME_BLACKLIST = ["antidebug.yar",
                            "Android*",
                            "*Ransomware*",
                            "ByteCode.MSIL.Ransomware*",
                            "Win32*",
                            "Win64*",]
    
    # Blacklist tên rule gốc (hỗ trợ wildcard pattern và regex)
    # Các rule có tên gốc khớp với pattern trong danh sách này sẽ bị bỏ qua
    # Mặc định: Loại bỏ rule có tên gợi ý PE/binary/Android/Ransomware/Payloads
    # LƯU Ý: Chỉ loại bỏ các rule RÕ RÀNG không liên quan đến web-based attacks
    # Giữ lại: backdoor, trojan, upload (có thể là web-based)
    ORIGINAL_RULE_NAME_BLACKLIST = [
        # Android và Windows executables (PE files - không phải web)
        r'^android_', r'^win32\.', r'^win64\.',
        # Linux binary/rootkit (binary files - không phải web)
        r'^linux\.(rootkit|virus)',  # Giữ lại trojan vì có thể là web trojan
        # Ransomware và packer (PE files - không phải web)
        r'ransomware', r'packer',
        # MSIL/.NET binary (compiled - không phải web)
        r'bytecode\.msil',
        # Crypto detection (không phải web attack)
        r'^crypto\.',
        # File extensions (binary files - không phải web)
        r'\.exe$', r'\.dll$', r'\.bin$', r'\.sys$',
        # Android (general - mobile, không phải web)
        r'android',
        # MacOS/iOS malware (mobile/desktop, không phải web)
        r'^macos\.', r'^osx\.', r'^ios\.', r'\.app$', r'\.dmg$',
        # Script malware CHỈ loại bỏ khi rõ ràng là desktop/system malware (không phải web)
        r'^powershell\.(malware|trojan)',  # Giữ lại backdoor vì có thể là web backdoor
        r'^vbscript\.(malware|trojan)',  # Giữ lại nếu không có malware/trojan
        r'^vba\.(malware|trojan|macro)',  # VBA macro trong Office - không phải web
        # Network/traffic rules (network layer, không phải file-based)
        r'^network\.', r'^traffic\.', r'^packet\.', r'^http\.(request|response|header)',
        # Email malware (email-based, không phải web upload)
        r'^email\.(malware|trojan|spam)', r'^mail\.(malware|trojan)', r'^eml\.(malware|trojan)',
        # IoT/embedded (firmware, không phải web)
        r'^iot\.', r'^embedded\.', r'^firmware\.',
        # Browser exploits (browser vulnerabilities, không phải uploaded files)
        r'^browser\.(exploit|vulnerability)', r'^chrome\.(exploit|vulnerability)',
        r'^firefox\.(exploit|vulnerability)', r'^ie\.(exploit|vulnerability)',
        # Flash exploits (browser plugin, không phải web shell)
        r'^flash\.(exploit|vulnerability)', r'\.swf$',
        # Registry rules (Windows system, không phải web)
        r'^registry\.',
    ]
    
    # Blacklist tên rule sau khi đổi tên (hỗ trợ wildcard pattern như abc*, test_*)
    # Các rule có tên sau khi đổi tên khớp với pattern trong danh sách này sẽ bị bỏ qua
    RENAMED_RULE_BLACKLIST = ["DarkenCode_antidebug*",
                              "DarkenCode_antidebug*",
                              "DarkenCode_packer*",
                              "DarkenCode_malicious_document*",
                              "DarkenCode_Warp*",
                              "DarkenCode_malware_Warp*",
                              "DarkenCode_Surtr*",
                              "DarkenCode_malware_Surtr*",
                              "DarkenCode_APT1*",
                              "DarkenCode_malware_APT1*",      
                              "nsacyber_extended_webshell_detection_possibleIndicator*",
                              "DarkenCode_Miscelanea_Linux_ldpreload*",
                              "DarkenCode_crypto*",
                              "DarkenCode_Cerberus_Cerberus*",
                              "DarkenCode_malware_Cerberus*",

                              ]

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip",
        "https://github.com/DarkenCode/yara-rules/archive/refs/heads/master.zip",
        "https://github.com/nsacyber/Mitigating-Web-Shells/archive/refs/heads/master.zip",
        "https://github.com/tenable/yara-rules/archive/refs/heads/master.zip"
    ]

    def __init__(self, debug, logger, application_path, debug_log=None):
        self.debug = debug
        self.logger = logger
        self.application_path = application_path
        # Biến toàn cục để tích lũy các rule đã compile thành công qua tất cả các file
        self.accumulated_rules = ""
        # File log duy nhất để ghi tất cả thông tin chi tiết
        # Nếu không chỉ định, sử dụng file log mặc định
        if debug_log is None:
            debug_log = os.path.join(application_path, 'upgrader.log')
        self.log_file = debug_log
        self.log_handle = None

    def _log(self, level, message, indent=0, console=False):
        """
        Ghi log vào file log
        Args:
            level: Mức độ log (INFO, WARNING, ERROR, DEBUG, NOTICE)
            message: Nội dung log
            indent: Số cấp độ thụt lề (0 = không thụt, 1 = 2 spaces, 2 = 4 spaces, ...)
            console: True nếu muốn in ra console, False nếu chỉ ghi vào file
        """
        # Luôn ghi vào file log
        if self.log_handle:
            try:
                timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
                indent_str = "  " * indent
                log_line = f"[{timestamp}] [{level}] {indent_str}{message}\n"
                self.log_handle.write(log_line)
                self.log_handle.flush()
            except Exception as exp:
                pass  # Bỏ qua lỗi ghi file
        
        # Chỉ in ra console nếu được yêu cầu và là level quan trọng (không phải DEBUG)
        # Logger sẽ tự động ghi vào file log riêng của nó và in ra console
        # DEBUG không in ra console, chỉ ghi vào file
        if console and self.logger:
            # Chỉ in ra console các level quan trọng
            important_levels = ['INFO', 'WARNING', 'ERROR', 'NOTICE', 'ALERT']
            if level.upper() in important_levels:
                try:
                    self.logger.log(level, "Upgrader", message)
                except:
                    pass

    def _log_console(self, level, message):
        """
        Ghi log vào file và in ra console (chỉ cho thông tin quan trọng: INFO, WARNING, ERROR, NOTICE)
        DEBUG không in ra console, chỉ ghi vào file
        """
        # Chỉ in ra console nếu là level quan trọng (không phải DEBUG)
        console_output = level.upper() in ['INFO', 'WARNING', 'ERROR', 'NOTICE', 'ALERT']
        self._log(level, message, indent=0, console=console_output)

    def _debug_log(self, message, indent=0):
        """
        Ghi log chi tiết vào file (không in ra console)
        """
        self._log("DEBUG", message, indent, console=False)
    
    def _log_traceback(self):
        """
        Ghi traceback vào file log và in ra console
        """
        import traceback
        import io
        # Lấy traceback dưới dạng string
        tb_str = io.StringIO()
        traceback.print_exc(file=tb_str)
        tb_content = tb_str.getvalue()
        
        # Ghi vào file log
        if self.log_handle:
            try:
                timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
                self.log_handle.write(f"[{timestamp}] [ERROR] Traceback:\n")
                for line in tb_content.split('\n'):
                    if line.strip():
                        self.log_handle.write(f"[{timestamp}] [ERROR]   {line}\n")
                self.log_handle.flush()
            except Exception:
                pass
        
        # In ra console nếu có logger
        if self.logger:
            try:
                # In từng dòng traceback
                for line in tb_content.split('\n'):
                    if line.strip():
                        self.logger.log("ERROR", "Upgrader", line)
            except Exception:
                pass
        
        # Vẫn in ra stderr để đảm bảo hiển thị
        traceback.print_exc()

    def _process_rules_and_log(self, content, total_rules_detected, total_rules_valid, total_rules_invalid):
        """
        Helper function để xử lý rules và log kết quả
        
        Returns:
            (accepted_rules, all_failed_rules, updated_detected, updated_valid, updated_invalid)
        """
        accepted_rules, failed_rules, total_count, valid_count, self.accumulated_rules = analyze_and_filter_rules_simple(
            content, self.accumulated_rules, self.logger, debug_log=self._debug_log)
        
        # Log kết quả
        self._debug_log(f"Rule processing results:", 1)
        self._debug_log(f"  Total rules: {total_count}", 2)
        self._debug_log(f"  Valid rules: {valid_count}", 2)
        self._debug_log(f"  Failed rules: {total_count - valid_count}", 2)
        if failed_rules:
            self._debug_log(f"  Failed rule details:", 2)
            for rule_name, error in failed_rules:
                self._debug_log(f"    - {rule_name}: {error}", 3)
        
        # Cập nhật biến đếm
        updated_detected = total_rules_detected + total_count
        updated_valid = total_rules_valid + valid_count
        updated_invalid = total_rules_invalid + (total_count - valid_count)
        
        return accepted_rules, failed_rules, updated_detected, updated_valid, updated_invalid
 
    def _match_pattern(self, text, pattern):
        """
        Kiểm tra xem text có khớp với pattern không
        Hỗ trợ cả wildcard pattern và regex pattern:
        - Wildcard: abc*, *abc, abc*def, *abc*, abc
        - Regex: r'win32\\.', r'\\.exe$', r'android', etc.
        
        Args:
            text: Chuỗi cần kiểm tra
            pattern: Pattern wildcard hoặc regex (có thể là raw string r'...' hoặc string thông thường)
        
        Returns:
            True nếu khớp, False nếu không
        """
        if not pattern:
            return False
        
        # Nếu pattern là string rỗng, không khớp
        pattern_str = str(pattern)
        if not pattern_str:
            return False
        
        # Kiểm tra xem pattern có phải là regex không (chứa các ký tự regex đặc biệt)
        # Nếu pattern chứa ^, $, \., \[, \(, \{, |, +, ?, * (nhưng không phải wildcard đơn giản)
        # thì coi như là regex pattern
        is_regex = False
        if any(char in pattern_str for char in ['^', '$', '\\', '[', '(', '{', '|', '+']):
            is_regex = True
        # Hoặc nếu pattern kết thúc bằng $ hoặc bắt đầu bằng ^, coi như regex
        if pattern_str.startswith('^') or pattern_str.endswith('$'):
            is_regex = True
        
        if is_regex:
            # Xử lý như regex pattern
            try:
                # Nếu pattern đã có ^ và $, dùng trực tiếp
                if pattern_str.startswith('^') and pattern_str.endswith('$'):
                    regex_pattern = pattern_str
                # Nếu chỉ có $ ở cuối, thêm ^ ở đầu
                elif pattern_str.endswith('$'):
                    regex_pattern = '^' + pattern_str
                # Nếu chỉ có ^ ở đầu, thêm $ ở cuối
                elif pattern_str.startswith('^'):
                    regex_pattern = pattern_str + '$'
                # Nếu không có ^ và $, thêm cả hai để khớp toàn bộ chuỗi
                else:
                    regex_pattern = '^' + pattern_str + '$'
                
                return bool(re.search(regex_pattern, text, re.IGNORECASE))
            except re.error:
                # Nếu pattern không phải là regex hợp lệ, thử kiểm tra như string thông thường
                return text == pattern_str
        else:
            # Xử lý như wildcard pattern
            # Nếu pattern không chứa wildcard, kiểm tra khớp chính xác (case-insensitive)
            if '*' not in pattern_str and '?' not in pattern_str:
                return text.lower() == pattern_str.lower()
            
            # Chuyển wildcard pattern thành regex
            # Escape các ký tự đặc biệt của regex trước (trừ * và ?)
            regex_pattern = re.escape(pattern_str)
            # Thay thế \* thành .* (khớp bất kỳ ký tự nào)
            regex_pattern = regex_pattern.replace(r'\*', '.*')
            # Thay thế \? thành . (khớp một ký tự)
            regex_pattern = regex_pattern.replace(r'\?', '.')
            # Đảm bảo khớp toàn bộ chuỗi
            regex_pattern = '^' + regex_pattern + '$'
            
            try:
                return bool(re.match(regex_pattern, text, re.IGNORECASE))
            except re.error:
                # Nếu pattern không phải là regex hợp lệ, thử kiểm tra như string thông thường
                return text.lower() == pattern_str.lower()

    def _is_in_blacklist(self, text, blacklist):
        """
        Kiểm tra xem text có khớp với bất kỳ pattern nào trong blacklist không
        
        Args:
            text: Chuỗi cần kiểm tra
            blacklist: Danh sách các pattern (hỗ trợ wildcard)
        
        Returns:
            True nếu khớp với bất kỳ pattern nào, False nếu không
        """
        if not blacklist:
            return False
        
        for pattern in blacklist:
            if self._match_pattern(text, pattern):
                return True
        return False

    def update_signatures(self, clean=False, debug_log_file=None):
        # Khởi tạo lại accumulated_rules cho mỗi lần update
        self.accumulated_rules = ""
        
        # Xóa file log cũ nếu tồn tại và mở file log mới
        if self.log_file:
            # Xóa file log cũ nếu tồn tại
            if os.path.exists(self.log_file):
                try:
                    os.remove(self.log_file)
                    self._log("INFO", f"Removed old log file: {self.log_file}")
                except Exception as e:
                    self._log("WARNING", f"Cannot remove old log file {self.log_file}: {e}")
            
            # Mở file log mới
            try:
                self.log_handle = open(self.log_file, 'w', encoding='utf-8')
                self.log_handle.write("=" * 80 + "\n")
                self.log_handle.write("YARA RULES PROCESSING LOG\n")
                self.log_handle.write(f"Started at: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_handle.write("=" * 80 + "\n\n")
                self._log_console("INFO", f"Logging enabled: {self.log_file}")
            except Exception as e:
                self._log_console("WARNING", f"Cannot open log file {self.log_file}: {e}")
                self.log_file = None
                self.log_handle = None
        
        # Biến đếm tổng số rule để báo cáo
        total_rules_detected = 0  # Tổng số rule phát hiện được
        total_rules_valid = 0     # Tổng số rule hợp lệ
        total_rules_invalid = 0   # Tổng số rule không hợp lệ
        
        # Preparations - Xóa và tạo lại các thư mục
        try:
            sigDir = os.path.join(self.application_path, os.path.abspath('libs/signature-base/'))
            
            # Nếu clean=True, xóa toàn bộ thư mục signature-base
            if clean:
                self._log_console("INFO", f"Cleaning directory '{sigDir}'")
                if os.path.exists(sigDir):
                    shutil.rmtree(sigDir)
            else:
                # Xóa toàn bộ nội dung trong các thư mục yara, iocs, misc
                for outDir in ['yara', 'iocs', 'misc']:
                    fullOutDir = os.path.join(sigDir, outDir)
                    if os.path.exists(fullOutDir):
                        self._log("INFO", f"Cleaning directory '{fullOutDir}'")  # Chỉ ghi vào file
                        # Xóa tất cả file và thư mục con trong thư mục này
                        for item in os.listdir(fullOutDir):
                            item_path = os.path.join(fullOutDir, item)
                            try:
                                if os.path.isdir(item_path):
                                    shutil.rmtree(item_path)
                                else:
                                    os.remove(item_path)
                            except Exception as e:
                                self._log("WARNING", f"Cannot remove {item_path}: {e}")
            
            # Tạo lại các thư mục nếu chưa tồn tại
            for outDir in ['', 'iocs', 'yara', 'misc']:
                fullOutDir = os.path.join(sigDir, outDir)
                if not os.path.exists(fullOutDir):
                    os.makedirs(fullOutDir)
        except Exception as e:
            if self.debug:
                self._log_traceback()
            self._log_console("ERROR", "Error while cleaning and creating the signature-base directories")
            sys.exit(1)
        
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                sig_author = sig_url.split('/')[3]
                # Downloading current repository
                try:
                    self._log_console("INFO", f"Downloading {sig_url} ...")
                    response = urlopen(sig_url)
                except Exception as e:
                    if self.debug:
                        self._log_traceback()
                    self._log_console("ERROR", "Error downloading the signature database - check your Internet connection")
                    sys.exit(1)

                # Read ZIP file
                try:
                    zipUpdate = zipfile.ZipFile(io.BytesIO(response.read()))
                    for zipFilePath in zipUpdate.namelist():
                        sigName = os.path.basename(zipFilePath)
                        if zipFilePath.endswith("/"):
                            continue
                        
                        # Extract the rules
                        self._log("DEBUG", f"Extracting {zipFilePath} ...")
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
                        # if "\\malware.yar" not in targetFile:
                        #     continue
                        # Kiểm tra FILE_NAME_BLACKLIST
                        if self._is_in_blacklist(sigName, self.FILE_NAME_BLACKLIST):
                            self._log("NOTICE", f"Skipping file '{sigName}' - in FILE_NAME_BLACKLIST")
                            self._debug_log(f"Skipping file '{sigName}' - matches FILE_NAME_BLACKLIST pattern", 1)
                            continue

                        # New file
                        if not os.path.exists(targetFile):
                            self._log("INFO", f"New signature file: {sigName}")

                        if zipFilePath.endswith(".yara") or zipFilePath.endswith(".yar"):
                            # Đọc nội dung trực tiếp từ zip để xử lý
                            with zipUpdate.open(zipFilePath) as source:
                                content = source.read().decode('utf-8', errors='replace')

                            # Replace } thành }\n khi } và rule xuất hiện trên cùng 1 dòng và } đứng trước rule
                            content = re.sub(r'}(?=[^\n]*rule)', r'}\n', content)
                            
                            # Tạo file rỗng để đảm bảo nếu quá trình xử lý bị lỗi, file sẽ không còn nội dung cũ
                            try:
                                with open(targetFile, 'w', encoding='utf-8') as f:
                                    f.write('')
                                self._debug_log(f"Cleared file content before processing: {targetFile}", 1)
                            except Exception as e:
                                self._log("WARNING", f"Cannot clear file {targetFile}: {e}")
                        else:
                            # Extract file cho các file không phải .yara/.yar
                            source = zipUpdate.open(zipFilePath)
                            target = open(targetFile, "wb")
                            with source, target:
                                shutil.copyfileobj(source, target)
                        
                        if zipFilePath.endswith(".yara") or zipFilePath.endswith(".yar"):
                            
                            # Log bắt đầu xử lý file
                            self._debug_log(f"{'='*80}", 0)
                            self._debug_log(f"Processing file: {sigName} at {dt.now().strftime('%Y-%m-%d %H:%M:%S')}", 0)
                            self._debug_log(f"{'='*80}", 0)
                            
                            # Chỉ xử lý thêm marker nếu file chưa có marker
                            if '//#########split#########' not in content:
                                
                                # Đánh dấu các dòng/đoạn bị comment để bỏ qua rule bị comment
                                commented_info = mark_commented_lines(content)
                                
                                # Tìm tên luật trong tệp và thêm marker để tách sau này
                                # Comment được giữ nguyên, không xóa
                                lines = content.split('\n')
                                new_lines = []
                                # Cờ để bỏ qua toàn bộ body của rule nếu rule thuộc blacklist (sau khi đổi tên)
                                skip_rule_body = False
                                # Dictionary để lưu mapping từ tên cũ sang tên mới
                                rule_name_mapping = {}
                                detected_rules = []  # Danh sách các rule phát hiện được
                                
                                self._debug_log(f"Scanning for rules in file...", 1)
                                
                                for line_num, line in enumerate(lines):
                                    # Kiểm tra xem dòng này có chứa rule declaration không
                                    # Match: "rule", "private rule", "global rule", "global private rule"
                                    # Pattern: (indent)(modifiers)rule (name)(rest)
                                    match = re.match(r'^(\s*)((?:private\s+|global\s+)*)rule\s+([^\s:{(]+)(\s*[:{].*)?', line)
                                    if match:
                                        # Nếu trước đó đang skip body của một rule trong blacklist,
                                        # thì gặp rule mới đồng nghĩa đã hết body của rule cũ -> reset cờ
                                        if skip_rule_body:
                                            skip_rule_body = False
                                        # Kiểm tra xem rule có bị comment không
                                        if is_rule_commented(line_num, line, commented_info):
                                            # Rule bị comment, bỏ qua (giữ nguyên dòng gốc)
                                            self._debug_log(f"Rule '{match.group(3)}' at line {line_num + 1} is commented, skipping", 2)
                                            new_lines.append(line)
                                            continue
                                        indent = match.group(1)
                                        rule_modifiers = match.group(2) if match.lastindex >= 2 else ""
                                        old_rule_name = match.group(3)
                                        rest = match.group(4) if match.lastindex >= 4 else ""
                                        
                                        # Log rule phát hiện được
                                        detected_rules.append({
                                            'name': old_rule_name,
                                            'line': line_num + 1,
                                            'modifiers': rule_modifiers.strip(),
                                            'in_comment': False
                                        })
                                        self._debug_log(f"Rule detected: '{old_rule_name}' at line {line_num + 1} (modifiers: '{rule_modifiers.strip()}')", 2)
                                        
                                        # Kiểm tra blacklist tên rule gốc (trước khi đổi tên)
                                        if self._is_in_blacklist(old_rule_name, self.ORIGINAL_RULE_NAME_BLACKLIST):
                                            # Rule nằm trong blacklist, bỏ qua
                                            detected_rules[-1]['in_comment'] = True  # Đánh dấu như đã bị skip
                                            self._debug_log(f"  -> Rule '{old_rule_name}' matches ORIGINAL_RULE_NAME_BLACKLIST pattern, skipping", 3)
                                            self._log("NOTICE", f"Skipping rule '{old_rule_name}' - matches ORIGINAL_RULE_NAME_BLACKLIST pattern (non-webshell rule)")
                                            # Giữ nguyên dòng gốc (không đổi tên, không thêm marker)
                                            new_lines.append(line)
                                            continue
                                        
                                        # Xử lý đổi tên và thêm marker cho rule
                                        
                                        # Kiểm tra độ dài tên rule gốc
                                        if len(old_rule_name) > 128:
                                            # Nếu tên gốc đã quá dài, cắt ngắn về 128 ký tự và dùng luôn
                                            new_rule_name = old_rule_name[:128]
                                        else:
                                            # Nếu tên gốc chưa đến 128 ký tự, tính số ký tự còn lại
                                            # Công thức: 128 - len(old_rule_name) - 2 (cho 2 dấu _)
                                            remaining_chars = 128 - len(old_rule_name) - 2
                                            
                                            if remaining_chars > 0:
                                                # Chia đôi số ký tự còn lại cho file_prefix và author_prefix
                                                prefix_len = remaining_chars // 2
                                                
                                                # Tạo file_prefix từ tên file
                                                file_prefix_raw = os.path.splitext(sigName)[0]  # Bỏ extension
                                                file_prefix_raw = re.sub(r'[^a-zA-Z0-9_]', '_', file_prefix_raw)  # Thay ký tự đặc biệt bằng _
                                                file_prefix = file_prefix_raw[:prefix_len]  # Cắt theo độ dài tính được
                                                
                                                # Tạo author_prefix từ sig_author
                                                author_prefix_raw = sig_author.replace(" ", "")
                                                author_prefix = author_prefix_raw[:prefix_len]  # Cắt theo độ dài tính được
                                                
                                                # Ghép lại: author_prefix_file_prefix_old_rule_name
                                                new_rule_name = f'{author_prefix}_{file_prefix}_{old_rule_name}'
                                                
                                                # Đảm bảo không vượt quá 128 ký tự (do làm tròn khi chia đôi)
                                                if len(new_rule_name) > 128:
                                                    # Nếu vẫn vượt, cắt ngắn thêm từ file_prefix và author_prefix
                                                    excess = len(new_rule_name) - 128
                                                    if len(file_prefix) >= excess:
                                                        file_prefix = file_prefix[:len(file_prefix) - excess]
                                                    elif len(author_prefix) >= excess:
                                                        author_prefix = author_prefix[:len(author_prefix) - excess]
                                                    new_rule_name = f'{author_prefix}_{file_prefix}_{old_rule_name}'
                                                    # Nếu vẫn vượt, cắt ngắn old_rule_name
                                                    if len(new_rule_name) > 128:
                                                        max_old_name_len = 128 - len(author_prefix) - len(file_prefix) - 2
                                                        if max_old_name_len > 0:
                                                            new_rule_name = f'{author_prefix}_{file_prefix}_{old_rule_name[:max_old_name_len]}'
                                                        else:
                                                            # Trường hợp cực kỳ hiếm: chỉ dùng prefix
                                                            new_rule_name = f'{author_prefix}_{file_prefix}'[:128]
                                            else:
                                                # Không đủ chỗ cho prefix, dùng luôn tên gốc
                                                new_rule_name = old_rule_name
                                        
                                        # Kiểm tra blacklist tên rule sau khi đổi tên (hỗ trợ wildcard pattern)
                                        if self._is_in_blacklist(new_rule_name, self.RENAMED_RULE_BLACKLIST):
                                            # Rule nằm trong blacklist: bỏ cả tên và toàn bộ body
                                            detected_rules[-1]['in_comment'] = True  # Đánh dấu như đã bị skip
                                            self._debug_log(
                                                f"  -> Rule '{old_rule_name}' -> '{new_rule_name}' matches RENAMED_RULE_BLACKLIST pattern, skipping whole rule",
                                                3
                                            )
                                            self._log(
                                                "NOTICE",
                                                f"Skipping rule '{old_rule_name}' (renamed to '{new_rule_name}') - matches RENAMED_RULE_BLACKLIST pattern (dropping full rule body)"
                                            )
                                            # Bật cờ để bỏ qua tất cả dòng body cho đến rule tiếp theo
                                            skip_rule_body = True
                                            continue
                                        
                                        # Lưu mapping
                                        rule_name_mapping[old_rule_name] = new_rule_name
                                        
                                        # Log đổi tên rule
                                        self._debug_log(f"  -> Renamed: '{old_rule_name}' -> '{new_rule_name}'", 3)
                                        
                                        # Giữ lại rule modifiers (private, global) khi đổi tên
                                        new_line = f'{indent}//#########split#########\n{rule_modifiers}rule {new_rule_name}{rest}'
                                        new_lines.append(new_line)
                                    else:
                                        # Không phải rule declaration
                                        if skip_rule_body:
                                            # Đang ở trong body của rule thuộc blacklist -> bỏ qua dòng này
                                            continue
                                        # Giữ nguyên các dòng còn lại
                                        new_lines.append(line)
                                
                                # Cập nhật content từ new_lines
                                content = '\n'.join(new_lines)
                                
                                # Log tổng kết rules phát hiện được
                                self._debug_log(f"Summary: Found {len(detected_rules)} rule(s) in file", 1)
                                for rule_info in detected_rules:
                                    status = "COMMENTED" if rule_info['in_comment'] else "ACTIVE"
                                    self._debug_log(f"  - {rule_info['name']} (line {rule_info['line']}, {status})", 2)
                                
                                if rule_name_mapping:
                                    self._debug_log(f"Rule name mappings ({len(rule_name_mapping)} rule(s)):", 1)
                                    for old_name, new_name in rule_name_mapping.items():
                                        self._debug_log(f"  {old_name} -> {new_name}", 2)
                                
                                # Cập nhật các reference đến rule name cũ trong condition
                                # LƯU Ý: Logic này chỉ áp dụng trong phạm vi MỘT FILE hiện tại
                                # Mỗi file có rule_name_mapping riêng, không ảnh hưởng đến file khác
                                # Vì YARA không hỗ trợ reference rule từ file khác, chỉ có thể reference trong cùng file
                                # Tìm các reference trong condition (ví dụ: condition: GlassesCode or GlassesStrings)
                                if rule_name_mapping:
                                    # Thay thế tất cả reference đến rule name cũ
                                    # Sắp xếp theo độ dài giảm dần để tránh thay thế nhầm (ví dụ: "Code" trong "GlassesCode")
                                    sorted_mappings = sorted(rule_name_mapping.items(), key=lambda x: len(x[0]), reverse=True)
                                    
                                    for old_name, new_name in sorted_mappings:
                                        # Tìm tất cả vị trí của old_name trong content
                                        # Sử dụng finditer để có thể kiểm tra từng match
                                        pattern = r'\b' + re.escape(old_name) + r'\b'
                                        matches = list(re.finditer(pattern, content))
                                        
                                        # Thay thế từ cuối lên đầu để không ảnh hưởng đến vị trí
                                        for match in reversed(matches):
                                            # Kiểm tra xem có nằm trong string không
                                            before_match = content[:match.start()]
                                            # Kiểm tra context gần nhất xem có đang ở trong block condition hay không
                                            # Ý tưởng: tìm dòng/section header gần nhất (condition/meta/strings/rule)
                                            lines_before = before_match.split('\n')
                                            last_section_line = None
                                            for prev_line in reversed(lines_before):
                                                stripped = prev_line.strip()
                                                if not stripped:
                                                    continue
                                                # Xác định các section header phổ biến
                                                if (stripped.startswith('condition:') or
                                                    stripped.startswith('strings:') or
                                                    stripped.startswith('meta:') or
                                                    stripped.startswith('rule ') or
                                                    stripped.startswith('private rule ') or
                                                    stripped.startswith('global rule ') or
                                                    stripped.startswith('global private rule ')):
                                                    last_section_line = stripped
                                                    break
                                            
                                            # Nếu section gần nhất không phải là condition: thì bỏ qua (không phải reference trong condition)
                                            if not last_section_line or not last_section_line.startswith('condition:'):
                                                continue

                                            # Đến đây: không nằm trong string, và đang ở trong phần condition -> có thể thay thế
                                            content = content[:match.start()] + new_name + content[match.end():]

                            accepted_rules = ""
                            all_failed_rules = []
                            
                            # Log accumulated_rules hiện tại
                            self._debug_log(f"Current accumulated_rules state:", 1)
                            if self.accumulated_rules:
                                self._debug_log(f"  Length: {len(self.accumulated_rules)} characters", 2)
                                current_rule_count = len(re.findall(r'^\s*rule\s+', self.accumulated_rules, re.MULTILINE))
                                self._debug_log(f"  Rules count: {current_rule_count}", 2)
                            else:
                                self._debug_log(f"  (empty)", 2)
                            
                            # Thử biên dịch cả file trước để kiểm tra nhanh
                            self._debug_log(f"Compiling entire file...", 1)
                            is_valid, error_msg = check_yara_rule(content)
                            
                            if is_valid:
                                self._debug_log(f"  Result: SUCCESS", 2)
                                # Nếu compile file OK, compile với accumulated_rules
                                self._debug_log(f"Compiling file with accumulated_rules...", 1)
                                test_with_accumulated = self.accumulated_rules + content + "\n"
                                is_valid_accumulated, error_msg_accumulated = check_yara_rule(test_with_accumulated)
                                
                                if is_valid_accumulated:
                                    self._debug_log(f"  Result: SUCCESS", 2)
                                    # Test match với file webshell mẫu
                                    self._debug_log(f"Testing rule match with sample file...", 1)
                                    is_match_valid, match_error_msg, matches_count = yara_rule_match(test_with_accumulated)
                                    
                                    if is_match_valid:
                                        self._debug_log(f"  Result: SUCCESS (matches: {matches_count})", 2)
                                        # Thêm cả file vào luôn (không cần check từng rule)
                                        # Tách rules và thêm tag ===SUCCESS=== cho tất cả
                                        import_lines = []
                                        for line in content.split('\n'):
                                            stripped = line.strip()
                                            # Chỉ match import nếu dòng không bắt đầu bằng // (không bị comment)
                                            if re.match(r'^import\s+".+?"', stripped) and not stripped.startswith('//'):
                                                import_lines.append(line)
                                        yara_imports = "\n".join(import_lines)

                                        # Loại bỏ imports khỏi content bằng cách thay thế từng dòng import thành ""
                                        rule_text_no_imports = content
                                        for import_line in import_lines:
                                            # Thay thế dòng import (kèm newline) thành chuỗi rỗng
                                            rule_text_no_imports = rule_text_no_imports.replace(import_line + '\n', '')
                                            # Nếu dòng import ở cuối file (không có newline sau)
                                            rule_text_no_imports = rule_text_no_imports.replace(import_line, '')
                                        
                                        # Kiểm tra xem file có marker không
                                        if '//#########split#########' in rule_text_no_imports:
                                            # File đã có marker, tách bằng marker
                                            parts = re.split(r'//#########split#########', rule_text_no_imports)
                                            addition_part = parts[0] if parts else ""
                                            yara_rules = parts[1:] if len(parts) > 1 else []
                                        else:
                                            # File chưa có marker, tách bằng cách tìm từ "rule" đến closing brace
                                            lines = rule_text_no_imports.split('\n')
                                            yara_rules = []
                                            current_rule = []
                                            brace_count = 0
                                            in_rule = False
                                            addition_part_lines = []

                                            # Đánh dấu các dòng/đoạn bị comment để bỏ qua rule bị comment
                                            commented_info_split = mark_commented_lines(rule_text_no_imports)
                                            
                                            for line_num, line in enumerate(lines):
                                                # Kiểm tra xem có phải rule declaration không
                                                if re.match(r'^\s*(?:private\s+|global\s+)*rule\s+', line):
                                                    # Kiểm tra xem rule có bị comment không
                                                    if is_rule_commented(line_num, line, commented_info_split):
                                                        # Rule bị comment, xử lý như phần không phải rule (giữ nguyên vào addition_part)
                                                        addition_part_lines.append(line)
                                                        continue
                                                    
                                                    if current_rule and in_rule:
                                                        # Lưu rule trước đó
                                                        yara_rules.append('\n'.join(current_rule))
                                                    current_rule = [line]
                                                    in_rule = True
                                                    # Đếm braces trong dòng này
                                                    brace_count = line.count('{') - line.count('}')
                                                elif in_rule:
                                                    current_rule.append(line)
                                                    brace_count += line.count('{') - line.count('}')
                                                    # Nếu đã đóng hết braces
                                                    if brace_count == 0:
                                                        # Lưu rule
                                                        yara_rules.append('\n'.join(current_rule))
                                                        current_rule = []
                                                        in_rule = False
                                                else:
                                                    # Phần không phải rule, thêm vào addition_part
                                                    addition_part_lines.append(line)
                                            
                                            # Nếu còn rule chưa đóng
                                            if current_rule and in_rule:
                                                yara_rules.append('\n'.join(current_rule))
                                            
                                            addition_part = '\n'.join(addition_part_lines).strip()
                                        
                                        accepted_rules = ""
                                        if yara_imports:
                                            accepted_rules += yara_imports + "\n"
                                        if addition_part.strip():
                                            accepted_rules += addition_part + "\n"
                                        
                                        # Nếu không tách được rules (có thể file không có marker và không tìm thấy rule declarations)
                                        if not yara_rules:
                                            # Ghi content gốc với tag ===SUCCESS=== ở đầu
                                            accepted_rules = f"//===SUCCESS===\n{content}\n"
                                            total_count = 1  # Coi như 1 rule
                                            self._debug_log(f"Warning: Could not split rules, writing entire content as one rule", 2)
                                        else:
                                            for rule in yara_rules:
                                                rule_text = rule.strip()
                                                if rule_text:
                                                    accepted_rules += f"//===SUCCESS===\n{rule_text}\n"
                                            total_count = len(yara_rules)
                                        
                                        # Cập nhật accumulated_rules
                                        self.accumulated_rules += content + "\n"
                                        
                                        # Đếm rules
                                        valid_count = total_count
                                        failed_rules = []
                                        all_failed_rules = []
                                        
                                        self._log_console("INFO", f"File {sigName}: Added entire file with {valid_count} rule(s) (compile and match test passed)")
                                        total_rules_detected += total_count
                                        total_rules_valid += valid_count
                                    else:
                                        self._debug_log(f"  Result: FAILED (match error: {match_error_msg})", 2)
                                        self._log_console("WARNING",f"File {sigName}: FAILED (match error: {match_error_msg})")
                                        # Match thất bại, check từng rule
                                        self._debug_log(f"Match test failed, processing rules individually...", 1)
                                        accepted_rules, failed_rules, total_rules_detected, total_rules_valid, total_rules_invalid = self._process_rules_and_log(
                                            content, total_rules_detected, total_rules_valid, total_rules_invalid)
                                        all_failed_rules.extend(failed_rules)
                                else:
                                    self._debug_log(f"  Result: FAILED (error: {error_msg_accumulated})", 2)
                                    self._log_console("WARNING", f"File {sigName}: FAILED (error: {error_msg_accumulated})")
                                    # Compile với accumulated_rules thất bại, check từng rule
                                    self._debug_log(f"Compile with accumulated_rules failed, processing rules individually...", 1)
                                    accepted_rules, failed_rules, total_rules_detected, total_rules_valid, total_rules_invalid = self._process_rules_and_log(
                                        content, total_rules_detected, total_rules_valid, total_rules_invalid)
                                    all_failed_rules.extend(failed_rules)
                            else:
                                self._debug_log(f"  Result: FAILED", 2)
                                self._debug_log(f"  Error: {error_msg}", 2)
                                self._log_console("WARNING", f"File {sigName} has error when compiling entire file: {error_msg}. Splitting into individual rules for checking...")
                                # Nếu compile file lỗi, tách từng rule và kiểm tra từng rule
                                self._log("WARNING", f"File {sigName} has error when compiling entire file: {error_msg}. Splitting into individual rules for checking...")
                                
                                self._debug_log(f"Processing rules in simple mode...", 1)
                                accepted_rules, failed_rules, total_rules_detected, total_rules_valid, total_rules_invalid = self._process_rules_and_log(
                                    content, total_rules_detected, total_rules_valid, total_rules_invalid)
                                all_failed_rules.extend(failed_rules)
                            
                            # Ghi file với accepted_rules (bao gồm cả rule thành công và rule lỗi đã comment)
                            # Mỗi file được ghi vào file gốc của nó (targetFile), không gộp chung
                            if accepted_rules.strip():
                                # Đếm số rule thành công (có tag ===SUCCESS===)
                                success_count = accepted_rules.count('//===SUCCESS===')
                                # Đếm số rule lỗi (có tag ===FAILED===)
                                failed_count = accepted_rules.count('//===FAILED===')
                                total_rule_count = success_count + failed_count
                                
                                if total_rule_count > 0:
                                    # Xác định file output
                                    output_target_file = targetFile
                                    
                                    # Kiểm tra compile lần cuối trước khi ghi (rule đã comment sẽ được bỏ qua)
                                    is_valid_final, error_msg_final = check_yara_rule(accepted_rules)

                                    if not is_valid_final:
                                        # Đến bước này mà còn lỗi: ghi nguyên accepted_rules ra file để người dùng debug
                                        self._log("WARNING", f"File {sigName}: Final compilation error: {error_msg_final}. Writing raw accepted_rules for manual debugging.")
                                        self._log_console("WARNING", f"File {sigName}: Final compilation error: {error_msg_final}. Writing raw accepted_rules for manual debugging.")
                                        self._debug_log(f"Final compilation error, writing raw accepted_rules (NO extra commenting) for debugging:", 1)
                                        self._debug_log(f"  File: {output_target_file}", 2)
                                        self._debug_log(f"  Error: {error_msg_final}", 2)
                                    else:
                                        self._log("INFO", f"File {sigName}: Writing {success_count} valid rule(s) and {total_rule_count - success_count} failed rule(s) to {output_target_file}")
                                    
                                    # Log chi tiết nội dung sẽ được ghi vào file
                                    self._debug_log(f"{'='*80}", 1)
                                    self._debug_log(f"WRITING TO FILE: {output_target_file}", 1)
                                    self._debug_log(f"{'='*80}", 1)
                                    self._debug_log(f"File path: {output_target_file}", 2)
                                    self._debug_log(f"Success rules: {success_count}", 2)
                                    self._debug_log(f"Failed rules: {total_rule_count - success_count}", 2)
                                    self._debug_log(f"Total rules: {total_rule_count}", 2)
                                    self._debug_log(f"Content length: {len(accepted_rules)} characters", 2)
                                    self._debug_log(f"{'='*80}", 1)
                                    
                                    with open(output_target_file, 'w', encoding='utf-8') as f:
                                        f.write(accepted_rules)
                                    
                                    # Log xác nhận đã ghi xong
                                    if is_valid_final:
                                        self._debug_log(f"✓ Successfully written to file: {output_target_file}", 2)
                                    else:
                                        self._debug_log(f"✓ Raw accepted_rules written to file despite compilation error (check above error and file content for debugging)", 2)
                                else:
                                    self._log("WARNING", f"File {sigName}: No valid rules found, skipping file write")
                                    self._debug_log(f"✗ SKIPPED FILE WRITE: No valid rules found", 1)
                                    self._debug_log(f"  File: {targetFile}", 2)
                                    self._debug_log(f"  accepted_rules was empty or had 0 rules", 2)
                            else:
                                self._log("WARNING", f"File {sigName}: No valid rules to write")
                                self._debug_log(f"✗ SKIPPED FILE WRITE: No valid rules to write", 1)
                                self._debug_log(f"  File: {targetFile}", 2)
                                self._debug_log(f"  accepted_rules was empty or whitespace only", 2)
                            
                            # Log tổng kết các rule lỗi (luôn thực thi)
                            if all_failed_rules:
                                unique_failed_rules = list(set([rule_name for rule_name, _ in all_failed_rules if rule_name]))
                                if unique_failed_rules:
                                    self._log("WARNING", f"File {sigName} has {len(unique_failed_rules)} rule(s) with errors (commented): {', '.join(unique_failed_rules)}")

                except Exception as e:
                    if self.debug:
                        self._log_traceback()
                    self._log_console("ERROR", "Error while extracting the signature files from the download package")
                    sys.exit(1)

        except Exception as e:
            if self.debug:
                self._log_traceback()
            return False
        
        # Summary report - in ra console và ghi vào file log
        self._log_console("INFO", "=" * 60)
        self._log_console("INFO", "YARA RULES PROCESSING SUMMARY REPORT")
        self._log_console("INFO", "=" * 60)
        self._log_console("INFO", f"Total rules detected: {total_rules_detected}")
        self._log_console("INFO", f"Total valid rules: {total_rules_valid}")
        self._log_console("INFO", f"Total invalid rules: {total_rules_invalid}")
        if total_rules_detected > 0:
            valid_percentage = (total_rules_valid / total_rules_detected) * 100
            self._log_console("INFO", f"Valid rules percentage: {valid_percentage:.2f}%")
        self._log_console("INFO", "=" * 60)
        
        # Ghi summary chi tiết vào log
        if self.log_handle:
            self._debug_log(f"{'='*80}", 0)
            self._debug_log(f"FINAL SUMMARY", 0)
            self._debug_log(f"{'='*80}", 0)
            self._debug_log(f"Total rules detected: {total_rules_detected}", 1)
            self._debug_log(f"Total valid rules: {total_rules_valid}", 1)
            self._debug_log(f"Total invalid rules: {total_rules_invalid}", 1)
            if total_rules_detected > 0:
                valid_percentage = (total_rules_valid / total_rules_detected) * 100
                self._debug_log(f"Valid rules percentage: {valid_percentage:.2f}%", 1)
            self._debug_log(f"Final accumulated_rules:", 1)
            self._debug_log(f"  Length: {len(self.accumulated_rules)} characters", 2)
            final_rule_count_summary = len(re.findall(r'^\s*rule\s+', self.accumulated_rules, re.MULTILINE))
            self._debug_log(f"  Rules count: {final_rule_count_summary}", 2)
        
        # Đóng file log
        if self.log_handle:
            try:
                self.log_handle.close()
                self._log_console("INFO", f"Log written to: {self.log_file}")
            except Exception as e:
                pass
        
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
        # Ghi lỗi vào stderr và console (hàm này được gọi trước khi khởi tạo logger)
        error_msg = "Error while evaluation of application path"
        print(error_msg, file=sys.stderr)
        traceback.print_exc()


if __name__ == '__main__':
    # Computername
    import argparse

    if platform == "windows":
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='YARA Rules Upgrader')
    parser.add_argument('--debug-log', type=str, default=None,
                       help='Path to debug log file (optional, default: upgrader_debug.log in application directory)')
    parser.add_argument('--no-debug-log', action='store_true',
                       help='Disable debug logging (do not create debug log file)')
    args = parser.parse_args()

    # Logger
    logger = Logger(t_hostname, platform=platform, caller='upgrader')

    # Xác định file log debug
    debug_log_file = None
    if not args.no_debug_log:
        if args.debug_log:
            debug_log_file = args.debug_log
        else:
            # Sử dụng file log mặc định
            app_path = get_application_path()
            logs_dir = os.path.join(app_path, 'logs')
            # Tạo thư mục logs nếu chưa tồn tại
            if not os.path.exists(logs_dir):
                try:
                    os.makedirs(logs_dir)
                except Exception as e:
                    # Ghi WARNING này vào file log nếu Updater đã được khởi tạo sau đó
                    logger.log("WARNING", "Upgrader", f"Cannot create logs directory {logs_dir}: {e}")
            debug_log_file = os.path.join(logs_dir, 'upgrader_debug.log')

    # Update
    updater = Updater(True, logger, get_application_path(), debug_log=debug_log_file)

    # Ghi log ra cả logger chung và file log riêng của upgrader
    logger.log("INFO", "Upgrader", "Updating Signatures ...")
    updater._log_console("INFO", "Updating Signatures ...")

    updater.update_signatures(False)

    # Mọi WARNING/ERROR quan trọng đã được ghi vào file log thông qua _log/_log_console/_debug_log
    logger.log("INFO", "Upgrader", "Update complete")
    updater._log_console("INFO", "Update complete")

    sys.exit(0)
