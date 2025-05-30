<?php

function test($var) {
    mysql_query(); // Essa aqui sera detectada
    echo $var;
}

test('Hello World');

// Exemplo de código PHP com vulnerabilidades
eval('echo "Hello World";'); // vulnerabilidade: uso de eval

$command = 'ls';
exec($command); // vulnerabilidade: uso de exec

// Adicionando um novo ponto vulneravel para garantir que a mudanca seja pega
$user_input = $_GET['name'];
echo "Bem vindo, " . $user_input; // Possivel XSS
?>