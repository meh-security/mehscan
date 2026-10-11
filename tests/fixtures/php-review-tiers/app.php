<?php
function ordinary_layout($title) { echo '<h1>' . htmlspecialchars($title, ENT_QUOTES) . '</h1>'; }
function request_near_fixed_include() { $search = $_GET['search']; require __DIR__ . '/fixed.php'; }
function fixed_include() { require __DIR__ . '/fixed.php'; }
function raw_request() { echo $_GET['name']; }
function encoded_request() { echo htmlspecialchars($_GET['name'], ENT_QUOTES); }
function numeric_request() { echo intval($_GET['number']); }
function stored_row(PDO $db) { $body = $db->query('SELECT body FROM comments')->fetchColumn(); echo $body; }
function stored_helper(PDO $db) { return $db->query('SELECT body FROM comments')->fetchColumn(); }
function render_stored_helper(PDO $db) { echo stored_helper($db); }
function request_helper() { return $_GET['name']; }
function render_request_helper() { echo request_helper(); }
function render_argument($text) { echo $text; }
function argument_route() { render_argument($_GET['name']); }
function named_slot($text, $unused) { echo $text; }
function named_route() { named_slot(unused: $_GET['name'], text: 'fixed'); }
function unpacked_slot($text) { echo $text; }
function unpacked_route() { unpacked_slot(...$_GET['values']); }
function stored_file() { $html = file_get_contents(__DIR__ . '/stored.html'); echo $html; }
function replaced_stored_row(PDO $db) { $body = $db->query('SELECT body FROM comments')->fetchColumn(); $body = 'fixed'; echo $body; }
function conditional_stored_row(PDO $db, $replace) { $body = $db->query('SELECT body FROM comments')->fetchColumn(); if ($replace) { $body = 'fixed'; } echo $body; }
function different_case(PDO $db) { $Body = $db->query('SELECT body FROM comments')->fetchColumn(); echo $body; }
class FakeReader { function fetchColumn() { return 'fixed'; } }
function fake_reader(FakeReader $reader) { echo $reader->fetchColumn(); }
function runtime_loader($plugin) { require $plugin; }
function request_loader() { require __DIR__ . '/templates/' . $_GET['view'] . '.php'; }
function install_code($code) { file_put_contents(__DIR__ . '/runtime.php', $code); }
function load_written_code() { require __DIR__ . '/runtime.php'; }
function raw_script($callback) { ?><script>let name = "<?php echo $callback; ?>";</script><?php }
function other_dangerous_operations($db, $sql, $cmd) { mysqli_query($db, $sql); system($cmd); }
function appended_stored_row(PDO $db, $tail) { $body = $db->query('SELECT body FROM comments')->fetchColumn(); $body .= $tail; echo $body; }
