<?php
namespace Local;
function curl_init($url) { return new LocalClient(); }
function curl_setopt($handle, $option, $value) { return true; }
function curl_exec($handle) { return ''; }
function local_curl() {
    $handle = curl_init($_GET['url']);
    curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($handle);
}
