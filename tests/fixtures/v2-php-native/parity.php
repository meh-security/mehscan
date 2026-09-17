<?php
function native_tls_options() {
    $handle = curl_init('https://example.com/');
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($handle);
}
namespace {
function stream_request() { return file_get_contents($_GET['url']); }
function stream_alias() { $url = $_POST['url']; return file_get_contents($url); }
function parsed_is_not_allowed() {
    $url = $_GET['url'];
    $parts = parse_url($url);
    return file_get_contents($url);
}
function unrelated_url_parse() {
    parse_url('https://approved.example/');
    return file_get_contents($_GET['url']);
}
function fixed_stream_path() { return file_get_contents('/srv/static.txt'); }
function fixed_stream_host() { return file_get_contents('https://approved.example/?q=' . $_GET['q']); }
function strong_password($password) { return password_hash($password, PASSWORD_DEFAULT); }
function weak_password($password, $storedDigest) { return md5($password) === $storedDigest; }
function checksum_only($data) { return md5($data); }
function weak_sha1($message, $expected) { return sha1($message) === $expected; }
}

namespace NativeAliases {
    use function \file_get_contents as read_stream;
    use function \parse_url as split_url;
    use function \md5 as legacy_digest;
    function imported_stream() { return read_stream($_GET['url']); }
    function imported_parse() { return split_url($_GET['url']); }
    function imported_digest($password, $digest) { return legacy_digest($password) === $digest; }
}
namespace Lookalikes {
    function file_get_contents($value) { return $value; }
    function parse_url($value) { return $value; }
    function md5($value) { return $value; }
    function local_stream() { return file_get_contents($_GET['url']); }
    function local_parse() { return parse_url($_GET['url']); }
    function local_digest($password) { return md5($password); }
}
// file_get_contents($_GET['comment']); md5($_GET['comment']);
