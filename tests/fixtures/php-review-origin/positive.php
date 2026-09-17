<?php
function execute_message() {
    $message = isset($_POST['message']) ? trim($_POST['message']) : '';
    // Keep the input producer outside the ordinary sink context window.
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
