<?php
function greet($name) {
    return "Hello " . htmlspecialchars($name);
}
echo greet("world");
