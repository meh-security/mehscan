<?php
function accumulated_html() {
    $html = '<p>';
    $html .= $_GET['message'];
    $html .= '</p>';
    echo $html;
}
function printed_html() { print $_GET['message']; }
function overwritten_html() {
    $html = $_GET['message'];
    $html = '<p>fixed</p>';
    print $html;
}
function numeric_not_text() {
    $html = $_GET['message'];
    $html += 1;
    echo $html;
}
function fixed_output() {
    $html = '<p>';
    $html .= 'fixed';
    $html .= '</p>';
    print $html;
}
function helper_replaces_output() {
    $html = $_GET['message'];
    replace_html($html);
    echo $html;
}
function helper_in_append_replaces_output() {
    $html = $_GET['message'];
    $html .= replace_html($html);
    echo $html;
}
function reference_replaces_output() {
    $html = $_GET['message'];
    $alias =& $html;
    $alias = 'fixed';
    echo $html;
}
