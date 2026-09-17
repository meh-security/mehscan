<?php
function conditional_command($value, $quoted) {
    $command = $quoted ? escapeshellarg($value) : $value;
    shell_exec('echo ' . $command);
}

function conditional_output($value, $encoded) {
    $output = $encoded ? htmlspecialchars($value, ENT_QUOTES, 'UTF-8') : $value;
    echo '<p>' . $output . '</p>';
}
