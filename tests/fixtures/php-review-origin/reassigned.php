<?php
function execute_message() {
    $message = $_POST['message'];
    $message = 'fixed';
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
