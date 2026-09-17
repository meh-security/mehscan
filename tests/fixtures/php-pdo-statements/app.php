<?php
function statement_parameters(PDO $database) {
    $statement = $database->prepare('SELECT name FROM users WHERE id = ?');
    $statement->execute([$_GET['id']]);
}
function statement_interpolated(PDO $database) {
    $statement = $database->prepare('SELECT name FROM users WHERE id = ' . $_GET['id']);
    $statement->execute([$_GET['other']]);
}
function statement_replaced(PDO $database) {
    $statement = $database->prepare('SELECT name FROM users WHERE id = ?');
    $statement = new LocalStatement();
    $statement->execute([$_GET['id']]);
}
function statement_helper(PDO $database) {
    $statement = $database->prepare('SELECT name FROM users WHERE id = ?');
    replace_statement($statement);
    $statement->execute([$_GET['id']]);
}
function statement_unknown($database) {
    $statement = $database->prepare('SELECT name FROM users WHERE id = ?');
    $statement->execute([$_GET['id']]);
}
function statement_other_owner() { $statement->execute([$_GET['id']]); }
function statement_conditional(PDO $database, $flag) {
    if ($flag) { $statement = $database->prepare('SELECT name FROM users WHERE id = ?'); }
    $statement->execute([$_GET['id']]);
}
