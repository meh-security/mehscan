<?php
function visible_database() {
    $db = new PDO('sqlite::memory:');
    $db->query($_GET['sql']);
}
function other_function_database() { $db->query($_GET['sql']); }
function replaced_database() {
    $db = new PDO('sqlite::memory:');
    $db = new LocalStore();
    $db->query($_GET['sql']);
}
function sibling_database($condition) {
    if ($condition) { $db = new PDO('sqlite::memory:'); }
    $db->query($_GET['sql']);
}
class First { public function handler(PDO $db) { $db->query($_GET['sql']); } }
class Second { public function handler($db) { $db->query($_GET['sql']); } }
function helper_may_replace_receiver() {
    $db = new PDO('sqlite::memory:');
    configure($db);
    $db->query($_GET['sql']);
}
