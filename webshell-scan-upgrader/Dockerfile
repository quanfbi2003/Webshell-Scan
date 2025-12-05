FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 1. Cài hệ thống + tools cần thiết (bước này được cache tốt)
RUN apt update && apt install -y \
    python3 python3-pip python3-dev \
    gcc git wget build-essential \
    yara libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Cài Python packages
RUN pip3 install --break-system-packages \
    colorama pandas pyinstaller yara-python

# Force rebuild từ đây trở đi mỗi lần build (nếu dùng --build-arg CACHEBUST=...)
ARG CACHEBUST=1 

# 3. Copy toàn bộ source code vào container
COPY upgrader.py /app/upgrader.py
COPY libs/logger.py /app/libs/logger.py
WORKDIR /app

# 4. Tự động tìm và chuẩn hóa cấu trúc cần thiết
RUN [ -f /app/upgrader.py ] || { echo "[ERROR] Không tìm thấy upgrader.py!"; exit 1; } && \
    [ -f /app/libs/logger.py ] || { echo "[ERROR] Không tìm thấy libs/logger.py!"; exit 1; } && \
    mkdir -p libs/signature-base && \
    [ -d /app/libs/signature-base ] || { echo "[ERROR] Không tìm thấy libs/signature-base/!"; exit 1; } && \
    echo "[OK] Source code đã sẵn sàng, bắt đầu build binary..."

# 5. Build binary bằng PyInstaller
RUN python3 -m PyInstaller --onefile --clean \
    --paths /app \
    --hidden-import libs.logger \
    --runtime-tmpdir ./ \
    upgrader.py && \
    cp dist/upgrader ./upgrader && \
    chmod +x upgrader && \
    ./upgrader --help >/dev/null 2>&1 && echo "[OK] Binary chạy thử thành công!" || echo "[WARN] Binary tạo xong nhưng chưa test --help"

# 6. Copy binary ra ngoài khi chạy container
CMD ["sh", "-c", "cp /app/upgrader /output/ && chmod +x /output/upgrader && echo '→ Đã copy upgrader vào thư mục hiện tại!'"]