<?php
require_once __DIR__ . '/includes/auth.php';
startSess();
session_unset();
session_destroy();
header('Location: index.php?logout=1');
exit;
