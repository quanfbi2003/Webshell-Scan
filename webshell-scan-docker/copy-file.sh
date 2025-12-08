#!/usr/bin/env bash
set -euo pipefail

# Thư mục gốc chứa các file nguồn (chỉnh lại nếu cần)
ROOT="."

# Thư mục đích
OUT="output"
# Dọn sạch thư mục đích trước khi copy mới
rm -rf "$OUT"
mkdir -p "$OUT"

# Danh sách file nguồn (tương đối so với ROOT)
cat <<'EOF' | while IFS= read -r relpath; do
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/nc
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/nc.1
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/php_webshell_1.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/php_webshell_5.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_7.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/static/img/header.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_10.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/music/poster/2022/04/check_test.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/notification/banner/2024/08/test_1.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/profile/avatar/2022/10/Ekd58J.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_12.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_14.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_5.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/php_webshell_2.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_11.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_13.php
source/tmp/cmsstage_1765096579_63d76423/admin_stage/upload/comingsoon/list/2025/10/test_9.php
EOF
  [ -z "$relpath" ] && continue
  src="$ROOT/$relpath"
  if [ ! -f "$src" ]; then
    echo "Bỏ qua: không tìm thấy $src" >&2
    continue
  fi
  newname="${relpath//\//--}"
  cp "$src" "$OUT/$newname"
done