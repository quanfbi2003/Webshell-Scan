<?php
function save_uploaded_avatar($file, $target) {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return false;
    }
    return move_uploaded_file($file['tmp_name'], $target);
}
?>
