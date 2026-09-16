<?php
namespace {
    function mysqli_real_query($connection, $sql) { return $sql; }
}
namespace Tenant {
    use function \mysqli_real_query as fake_query;
    function qualified_global_lookalike($connection) { \mysqli_real_query($connection, $_GET['sql']); }
    function imported_global_lookalike($connection) { fake_query($connection, $_GET['sql']); }
}
