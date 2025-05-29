<?php

function test($var) {
    mysql_query();
    echo $var;
}

test('Hello World');

// Exemplo de código PHP com vulnerabilidades
eval('echo "Hello World";'); // vulnerabilidade: uso de eval

$command = 'ls';
exec($command); // vulnerabilidade: uso de exec
?>