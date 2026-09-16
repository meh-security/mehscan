<?php
namespace Tenant {
    use function \shell_exec as launch;
    use \PDO as NativeDatabase;
    function shell_exec($input) { return $input; }
    function local_lookalike() { shell_exec($_GET['input']); }
    function global_api() { \ShElL_ExEc($_GET['input']); }
    function imported_api() { launch($_GET['input']); }
    function variable_callable($launch) { $launch($_GET['input']); }
    function imported_database(NativeDatabase $db) { $db->query($_GET['sql']); }
    class PDO { public function query($value) { return $value; } }
    function local_database() { $db = new PDO(); $db->query($_GET['sql']); }
    function unknown_receiver($db) { $db->query($_GET['sql']); }
}
namespace Other {
    function alias_does_not_leak() { launch($_GET['input']); }
    function fallback_unknown() { shell_exec($_GET['input']); }
    function native_eval() { eval($_POST['code']); }
    function qualified_eval_lookalike() { \eval($_POST['code']); }
}
