<?php
$db = new SQLite3('test.db');
$db->exec('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, name TEXT)');
$db->exec('INSERT INTO test(name) VALUES ("Hello SQLite")');

$result = $db->query('SELECT * FROM test');
while ($row = $result->fetchArray()) {
    print_r($row);
}
?>