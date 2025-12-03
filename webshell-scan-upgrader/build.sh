#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

echo "=== Build Webshell Upgrader từ: $SCRIPT_DIR ==="

# Dọn dẹp cũ
rm -rf dist/ build/ *.spec upgrader 2>/dev/null || true
docker rmi upgrader-builder 2>/dev/null || true
docker builder prune -f >/dev/null 2>&1

echo "=== Đang build Docker image (có thể dùng cache cho base + apt) ==="
# Dùng timestamp để force rebuild từ phần copy source trở đi (nếu cần)
docker build \
    --build-arg CACHEBUST=$(date +%s) \
    -f "$DOCKERFILE" \
    -t upgrader-builder \
    "$SCRIPT_DIR"

echo "=== Chạy PyInstaller trong container để tạo binary ==="
docker run --rm \
    -v "$SCRIPT_DIR:/output" \
    upgrader-builder

# Kiểm tra kết quả
if [[ -f "$SCRIPT_DIR/upgrader" && -s "$SCRIPT_DIR/upgrader" ]]; then
    chmod +x "$SCRIPT_DIR/upgrader"
    echo ""
    echo "HOÀN TẤT 100%!"
    echo "File binary: $SCRIPT_DIR/upgrader"
    echo "Kích thước: $(du -h "$SCRIPT_DIR/upgrader" | cut -f1)"
    echo ""
    echo "Chạy thử: ./upgrader --help"
    echo "Hoặc:    ./upgrader --update"
else
    echo ""
    echo "LỖI: Không tạo được file upgrader!"
    echo "Nguyên nhân thường gặp:"
    echo "   • Thiếu file upgrader.py trong thư mục gốc"
    echo "   • Thiếu thư mục libs/ hoặc libs/logger.py"
    echo "   • Thiếu thư mục libs/signature-base/"
    echo "   • YARA rule không compile được (xem log Docker build)"
    exit 1
fi