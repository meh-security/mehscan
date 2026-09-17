<?php
namespace Local;
function json_decode($text, $associative) { return ['hostname' => 'example.com']; }
function lookalike() {
    $body = json_decode(\file_get_contents('php://input'), true);
    \shell_exec($body['hostname']);
}
