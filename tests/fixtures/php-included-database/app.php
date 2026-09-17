<?php
function included_pdo() {
    require __DIR__ . '/config.php';
    $query = 'SELECT name FROM users WHERE id = ' . $_GET['id'];
    $database->query($query);
}
function included_mysqli() {
    include __DIR__ . '/config.php';
    $query = 'SELECT name FROM users WHERE id = ' . $_GET['id'];
    $connection->query($query);
}
function included_fixed() {
    require __DIR__ . '/config.php';
    $database->query('SELECT name FROM users');
}
function relative_unknown() {
    require 'config.php';
    $database->query($_GET['query']);
}
function dynamic_unknown($path) {
    require $path;
    $database->query($_GET['query']);
}
function conditional_unknown($flag) {
    if ($flag) { require __DIR__ . '/config.php'; }
    $database->query($_GET['query']);
}
function reassigned_unknown() {
    require __DIR__ . '/config.php';
    $database = new LocalDatabase();
    $database->query($_GET['query']);
}
function helper_unknown() {
    require __DIR__ . '/config.php';
    replace_database($database);
    $database->query($_GET['query']);
}
function additional_include_unknown($path) {
    require __DIR__ . '/config.php';
    include $path;
    $database->query($_GET['query']);
}
function replaced_local_origin($path) {
    $database = new PDO('sqlite::memory:');
    include $path;
    $database->query($_GET['query']);
}
function sibling_owner() { $database->query($_GET['query']); }
