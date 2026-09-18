<?php

function extended_document_query(array $filter) {
    return new \MongoDB\Driver\Query($filter);
}
