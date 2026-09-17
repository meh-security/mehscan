<?php
function json_command() {
    $body = json_decode(file_get_contents('php://input'), true);
    $hostname = $body['hostname'] ?? '';
    $command = 'nslookup ' . $hostname;
    shell_exec($command);
}
function json_html() {
    $body = json_decode(file_get_contents('php://input'), true);
    echo $body['message'];
}
function json_fixed_command() {
    $body = json_decode(file_get_contents('php://input'), true);
    $hostname = $body['hostname'];
    shell_exec('nslookup example.com');
}
function json_replaced() {
    $body = json_decode(file_get_contents('php://input'), true);
    $body = ['hostname' => 'example.com'];
    shell_exec($body['hostname']);
}
function json_field_replaced() {
    $body = json_decode(file_get_contents('php://input'), true);
    $body['hostname'] = 'example.com';
    shell_exec($body['hostname']);
}
function json_helper_mutated() {
    $body = json_decode(file_get_contents('php://input'), true);
    replace_body($body);
    shell_exec($body['hostname']);
}
function json_conditional($condition) {
    if ($condition) { $body = json_decode(file_get_contents('php://input'), true); }
    shell_exec($body['hostname']);
}
function json_file() {
    $body = json_decode(file_get_contents('settings.json'), true);
    shell_exec($body['hostname']);
}
function json_object() {
    $body = json_decode(file_get_contents('php://input'));
    shell_exec($body['hostname']);
}
function other_owner() { shell_exec($body['hostname']); }
function json_reference() {
    $body = json_decode(file_get_contents('php://input'), true);
    $alias =& $body;
    $alias['hostname'] = 'example.com';
    shell_exec($body['hostname']);
}
function json_try_branch($protect) {
    try {
        $body = json_decode(file_get_contents('php://input'), true);
        $hostname = $body['hostname'] ?? '';
        if (empty($hostname)) { return; }
        $command = $protect ? escapeshellcmd('nslookup ' . escapeshellarg($hostname)) : 'nslookup ' . $hostname;
        shell_exec($command);
    } catch (Exception $error) { }
}
function json_condition_is_not_data() {
    $body = json_decode(file_get_contents('php://input'), true);
    $hostname = $body['hostname'];
    $command = $hostname ? 'nslookup example.com' : 'nslookup example.org';
    shell_exec($command);
}
function json_branch_overwrite($flag) {
    $body = json_decode(file_get_contents('php://input'), true);
    $hostname = $body['hostname'];
    if ($flag) { $hostname = 'example.com'; } else { $hostname = 'example.org'; }
    $command = 'nslookup ' . $hostname;
    shell_exec($command);
}
function json_split_body() {
    $raw = file_get_contents('php://input');
    $body = json_decode($raw, true);
    shell_exec($body['command']);
}
function json_split_replaced() {
    $raw = file_get_contents('php://input');
    $raw = '{"command":"fixed"}';
    $body = json_decode($raw, true);
    shell_exec($body['command']);
}
function json_split_mutated() {
    $raw = file_get_contents('php://input');
    replace_body($raw);
    $body = json_decode($raw, true);
    shell_exec($body['command']);
}
function json_object_sql() {
    $raw = file_get_contents('php://input');
    $body = json_decode($raw);
    if (is_null($body)) { return; }
    mysqli_query($database, 'SELECT name FROM users WHERE id = ' . $body->id);
}
function json_object_explicit() {
    $body = json_decode(file_get_contents('php://input'), false);
    echo $body->message;
}
function json_wrong_object_mode() {
    $body = json_decode(file_get_contents('php://input'), true);
    shell_exec($body->command);
}
function json_object_field_replaced() {
    $body = json_decode(file_get_contents('php://input'));
    $body->command = 'fixed';
    shell_exec($body->command);
}
function json_dynamic_property($property) {
    $body = json_decode(file_get_contents('php://input'));
    shell_exec($body->$property);
}
