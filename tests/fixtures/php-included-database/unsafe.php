<?php
function mutating_config() {
    require __DIR__ . '/unsafe-config.php';
    $database->query($_GET['query']);
}
