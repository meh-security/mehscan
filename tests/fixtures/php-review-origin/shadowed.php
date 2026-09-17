<?php
function unrelated() {
    $message = $_POST['message'];
}
function execute_message($message) {
    // 1
    // 2
    // 3
    // 4
    // 5
    // 6
    // 7
    // 8
    // 9
    // 10
    // 11
    // 12
    $command = 'echo ' . $message;
    shell_exec($command);
}
