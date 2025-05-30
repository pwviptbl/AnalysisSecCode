<?php

function test($var) {
    mysql_query();
    echo $var;
}

test('Hello World');

eval('echo "Hello World";');
$command = 'ls';
exec($command);

$user_input = $_GET['name'];
echo "Bem vindo, " . $user_input;
?>