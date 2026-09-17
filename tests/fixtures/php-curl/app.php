<?php
function curl_input() {
    $handle = curl_init($_GET['url']);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_exec($handle);
}
function curl_selected() {
    $handle = curl_init();
    curl_setopt($handle, CURLOPT_URL, $_POST['url']);
    curl_exec($handle);
}
function curl_replaced_url() {
    $handle = curl_init($_GET['url']);
    curl_setopt($handle, CURLOPT_URL, 'https://example.com/');
    curl_exec($handle);
}
function curl_unknown_option($option) {
    $handle = curl_init($_GET['url']);
    curl_setopt($handle, $option, 'https://example.com/');
    curl_exec($handle);
}
function curl_unknown_helper() {
    $handle = curl_init($_GET['url']);
    replace_handle($handle);
    curl_exec($handle);
}
function curl_replaced_handle() {
    $handle = curl_init($_GET['url']);
    $handle = new LocalClient();
    curl_exec($handle);
}
function curl_option_array() {
    $handle = curl_init($_GET['url']);
    curl_setopt_array($handle, [CURLOPT_URL => 'https://example.com/']);
    curl_exec($handle);
}
function curl_unchecked_https() {
    $handle = curl_init('https://example.com/');
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 0);
    curl_exec($handle);
}
function curl_checked_https() {
    $handle = curl_init('https://example.com/');
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 2);
    curl_exec($handle);
}
function curl_fixed_http() {
    $handle = curl_init('http://example.com/');
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($handle);
}
function curl_unused_https() {
    $handle = curl_init('https://example.com/');
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
}
function other_curl_owner() { curl_exec($handle); }
