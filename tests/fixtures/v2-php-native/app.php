<?php
function direct_command() {
    shell_exec($_GET['command']);
}
function alias_command() {
    $input = $_POST['host'];
    $copy = $input;
    $command = 'ping ' . $copy;
    shell_exec($command);
}
function interpolated_sql(PDO $db) {
    $input = $_GET['id'];
    $sql = "SELECT name FROM records WHERE id = '$input'";
    $db->query($sql);
}
function unsafe_prepare(PDO $db) {
    $db->prepare('SELECT name FROM records WHERE id = ' . $_GET['id']);
}
function mysqli_sql($connection) {
    $input = $_GET['id'];
    mysqli_query($connection, 'SELECT name FROM records WHERE id = ' . $input);
}
function prepared_safe(PDO $db) {
    $input = $_GET['id'];
    $sql = 'SELECT name FROM records WHERE id = ?';
    $statement = $db->prepare($sql);
    $statement->execute([$input]);
}
function bound_safe($connection) {
    mysqli_execute_query($connection, 'SELECT name FROM records WHERE id = ?', [$_GET['id']]);
}
function reflected_html() {
    $input = $_GET['name'];
    echo '<p>' . $input . '</p>';
}
function encoded_html() {
    $input = $_GET['name'];
    echo '<p>' . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . '</p>';
}
function script_encoding_is_not_protection() {
    $input = $_GET['name'];
    echo '<script>const value = "' . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . '";</script>';
}
function unrelated_control() {
    htmlspecialchars($_GET['other'], ENT_QUOTES, 'UTF-8');
    echo $_GET['name'];
}
function reassigned_safe() {
    $input = $_GET['name'];
    $input = 'fixed';
    echo $input;
}
function branch_only_control($condition) {
    $input = $_GET['name'];
    if ($condition) { $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8'); }
    echo $input;
}
function mixed_controls($connection) {
    $input = $_GET['command'];
    mysqli_execute_query($connection, 'SELECT name FROM records WHERE id = ?', [$input]);
    shell_exec($input);
}
function other_boundaries() {
    file_get_contents($_GET['path']);
    file_put_contents($_GET['destination'], 'fixed');
    unserialize($_COOKIE['payload'], ['allowed_classes' => false]);
    eval($_POST['code']);
}
function normalization_is_not_containment() {
    file_get_contents(realpath($_GET['path']));
}
function quoting_is_not_executable_authorization() {
    shell_exec(escapeshellarg($_GET['command']));
}
function literal_safe() {
    $sql = 'SELECT name FROM public_catalog';
    shell_exec('uptime');
    echo '<p>fixed</p>';
    file_get_contents('/srv/static.txt');
}
function no_call_graph($unrelated) {
    $input = $_GET['name'];
    $unknown = transform($input);
    echo $unknown;
}
function named_argument_unknown() {
    shell_exec(command: $_GET['command']);
}
function unpacked_arguments_unknown() {
    shell_exec(...$_GET['arguments']);
}
function inline_helper_unknown() {
    shell_exec(transform($_GET['command']));
}
function unsafe_execute_query($connection) {
    mysqli_execute_query($connection, 'SELECT name FROM records WHERE id = ' . $_GET['id'], []);
}
function uppercase_output() {
    ECHO $_GET['name'];
}
// shell_exec($_GET['comment']);
/* mysqli_query($connection, $_GET['comment']); */
$inert = 'shell_exec($_GET["string"]);';
function mysqli_method_input(mysqli $db) { $db->query($_GET['sql']); }
function mysqli_method_constructed() {
    $db = new mysqli('localhost', 'user', 'password', 'database');
    $db->real_query('SELECT name FROM records WHERE id = ' . $_GET['id']);
}
function mysqli_method_bound(mysqli $db) {
    $db->execute_query('SELECT name FROM records WHERE id = ?', [$_GET['id']]);
}
function mysqli_method_replaced(mysqli $db) { $db = unknown_database(); $db->query($_GET['sql']); }
function mysqli_method_helper(mysqli $db) { replace_database($db); $db->query($_GET['sql']); }
function mysqli_method_conditional() {
    if ($_GET['mode']) { $db = new mysqli(); }
    $db->query($_GET['sql']);
}
function mysqli_method_unknown($db) { $db->query($_GET['sql']); }
function unsafe_include() { include $_GET['file']; }
function unsafe_require() { require_once $_POST['file']; }
function fixed_include() { include '/srv/templates/header.php'; }
function unsafe_upload_move() { move_uploaded_file($_FILES['file']['tmp_name'], '/srv/uploads/' . $_FILES['file']['name']); }
function fixed_upload_move() { move_uploaded_file($_FILES['file']['tmp_name'], '/srv/private/server-owned.bin'); }
function unsafe_redirect() { header('Location: ' . $_GET['next']); }
function fixed_redirect() { header('Location: /home'); }
function unrelated_header() { header('X-Message: ' . $_GET['message']); }
function misleading_header() { header('X-Message: ' . 'Location: ' . $_GET['next']); }
function ldap_filter($connection) { ldap_search($connection, 'dc=example,dc=org', $_GET['filter']); }
