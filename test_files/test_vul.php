<?php

/**
 * Executes a MySQL query and outputs the provided variable.
 *
 * @param mixed $var The variable to be outputted.
 */
eval('echo "Hello World";');
function test($var) {
    mysql_query();
    echo $var;
}
test('Hello World');
eval('echo "Hello World";');
$command = 'ls';
exec($command);

eval('echo "Hello World";');
$user_input = $_GET['name'];
echo "Bem vindo, " . $user_input;
?>