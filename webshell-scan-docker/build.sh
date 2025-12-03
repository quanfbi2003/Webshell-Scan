#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

echo "=== Build Webshell Scanner từ: $SCRIPT_DIR ==="

# Dọn dẹp cũ
rm -rf dist/ build/ *.spec webshell-scan 2>/dev/null || true
docker rmi ws-builder 2>/dev/null || true
docker builder prune -f >/dev/null 2>&1

echo "=== Đang build Docker image (có thể dùng cache cho base + apt) ==="
# Dùng timestamp để force rebuild từ phần copy source trở đi (nếu cần)
docker build \
    --build-arg CACHEBUST=$(date +%s) \
    -f "$DOCKERFILE" \
    -t ws-builder \
    "$SCRIPT_DIR"

echo "=== Chạy PyInstaller trong container để tạo binary ==="
docker run --rm \
    -v "$SCRIPT_DIR:/output" \
    ws-builder

# Kiểm tra kết quả
if [[ -f "$SCRIPT_DIR/webshell-scan" && -s "$SCRIPT_DIR/webshell-scan" ]]; then
    chmod +x "$SCRIPT_DIR/webshell-scan"
    echo ""
    echo "HOÀN TẤT 100%!"
    echo "File binary: $SCRIPT_DIR/webshell-scan"
    echo "Kích thước: $(du -h "$SCRIPT_DIR/webshell-scan" | cut -f1)"
    echo ""
    echo "Chạy thử: ./webshell-scan --help"
else
    echo ""
    echo "LỖI: Không tạo được file webshell-scan!"
    echo "Nguyên nhân thường gặp:"
    echo "   • Thiếu file webshell-scan.py trong thư mục gốc project"
    echo "   • Thiếu thư mục libs/ hoặc libs/logger.py"
    echo "   • Thiếu thư mục libs/signature-base/"
    echo "   • YARA rule không compile được (xem log Docker build)"
    exit 1
fi
