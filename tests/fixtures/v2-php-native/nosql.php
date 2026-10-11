<?php

function execute_filter(MongoDB\Driver\Manager $database, $filter) {
    $query = new MongoDB\Driver\Query($filter);
    return $database->executeQuery('app.users', $query);
}
