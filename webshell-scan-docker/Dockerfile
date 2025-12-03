FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 1. Cài hệ thống + tools cần thiết (bước này được cache tốt)
RUN apt update && apt install -y \
    python3 python3-pip python3-dev \
    gcc git wget build-essential \
    libfuzzy-dev \
    yara libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Cài Python packages
RUN pip3 install --break-system-packages colorama psutil netaddr pandas pyssdeep yara-python openpyxl pyinstaller requests

# Force rebuild từ đây trở đi mỗi lần build (nếu dùng --build-arg CACHEBUST=...)
ARG CACHEBUST=1

# 3. Copy toàn bộ source code vào container
COPY . /app
WORKDIR /app

# 4. Tự động tìm và chuẩn hóa cấu trúc cần thiết
RUN mkdir -p libs config logs quarantine && \
    # Tìm webshell-scan.py
    find /app -name "webshell-scan.py" -type f -exec cp {} /app/webshell-scan.py \; -quit && \
    [ -f /app/webshell-scan.py ] || { echo "[ERROR] Không tìm thấy webshell-scan.py!"; exit 1; } && \
    \
    # Tìm và copy logger.py vào /app/libs/
    find /app -name "logger.py" -path "*/libs/*" -type f -exec cp {} /app/libs/logger.py \; -quit 2>/dev/null || true && \
    [ -f /app/libs/logger.py ] || { echo "[ERROR] Không tìm thấy libs/logger.py!"; exit 1; } && \
    \
    # Tìm và copy toàn bộ signature-base
    find /app -type d -name "signature-base" -exec cp -r {} /app/libs/ \; -quit 2>/dev/null || true && \
    [ -d /app/libs/signature-base ] || { echo "[ERROR] Không tìm thấy libs/signature-base/!"; exit 1; } && \
    \
    touch /app/libs/__init__.py && \
    echo "[OK] Source code đã sẵn sàng, bắt đầu build binary..."

# 5. Chuẩn bị cấu trúc fuzzy_64.so cho pyssdeep
RUN PYSSDEEP_PATH=$(python3 -c "import pyssdeep, os; print(os.path.dirname(pyssdeep.__file__))" 2>/dev/null || echo "") && \
    if [ -z "$PYSSDEEP_PATH" ]; then \
        echo "[ERROR] pyssdeep not found. Reinstalling..." && \
        pip3 install --break-system-packages pyssdeep --force-reinstall && \
        PYSSDEEP_PATH=$(python3 -c "import pyssdeep, os; print(os.path.dirname(pyssdeep.__file__))"); \
    fi && \
    FUZZY_SRC="$PYSSDEEP_PATH/bin/linux/fuzzy_64.so" && \
    if [ ! -f "$FUZZY_SRC" ]; then \
        echo "[ERROR] Not found: $FUZZY_SRC" && exit 1; \
    fi && \
    mkdir -p _pyssdeep_bundle/bin/linux/fuzzy_64.so && \
    cp "$FUZZY_SRC" _pyssdeep_bundle/bin/linux/fuzzy_64.so/fuzzy_64.so

# 6. Build binary bằng PyInstaller
RUN PYSSDEEP_PATH=$(python3 -c "import pyssdeep, os; print(os.path.dirname(pyssdeep.__file__))") && \
    python3 -m PyInstaller --onefile --clean \
        --add-data "$PYSSDEEP_PATH:pyssdeep" \
        --add-data "_pyssdeep_bundle/bin/linux:fuzzy_64.so" \
        --add-data "libs/signature-base:libs/signature-base" \
        --collect-all libs \
        --hidden-import pyssdeep \
        --hidden-import pyssdeep.ssdeep_wrapper \
        --hidden-import libs.helpers \
        --hidden-import libs.logger \
        --runtime-tmpdir ./ \
        webshell-scan.py && \
    cp -f dist/webshell-scan ./webshell-scan && \
    chmod +x webshell-scan && \
    ./webshell-scan --help >/dev/null 2>&1 && echo "[OK] Binary chạy thử thành công!" || echo "[WARN] Binary tạo xong nhưng chưa test --help"

# 7. Copy binary ra ngoài khi chạy container (giống logic upgrader)
CMD ["sh", "-c", "cp /app/webshell-scan /output/ && chmod +x /output/webshell-scan && echo '→ Đã copy webshell-scan vào thư mục hiện tại!'"]