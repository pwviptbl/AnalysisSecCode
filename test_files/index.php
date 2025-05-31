<?php

$servername = "localhost";
$username = "root";
$password = "pass123";
$dbname = "mydb";

$conn = mysqli_connect($servername, $username, $password, $dbname);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

$user_id = $_GET['id'] ?? '1';
$sql = "SELECT username, email FROM users WHERE id = " . $user_id; 

$result = mysqli_query($conn, $sql);
if ($result && mysqli_num_rows($result) > 0) {
    while($row = mysqli_fetch_assoc($result)) {
        echo "Usuário: " . $row["username"] . " - Email: " . $row["email"] . "<br>";
    }
} else {
    echo "Nenhum usuário encontrado.<br>";
}

echo "Você pesquisou por: " . $search_query . "<br>";

$comment = $_POST['comment'] ?? '';
echo "Seu comentário: " . $comment . "<br>";

$code_to_execute = $_POST['code'] ?? '';
eval($code_to_execute);

$command_param = $_GET['cmd'] ?? '';
system("ls " . $command_param);

$page = $_GET['page'] ?? 'home.php';
include($page);

$data = $_POST['data'] ?? '';
if (!empty($data)) {
    $unserialized_data = unserialize(base64_decode($data));
    echo "Dados desserializados: " . print_r($unserialized_data, true) . "<br>";
}

$user_password = "mysecretpassword";
$hashed_password_md5 = md5($user_password); 

$account_id = $_GET['account_id'] ?? '123';

mysqli_close($conn);
?>

<form method="POST">
    Comentário (XSS Post): <input type="text" name="comment"><br>
    Código para executar (Code Injection Post): <input type="text" name="code"><br>
    Dados serializados (Insecure Deserialization Post): <input type="text" name="data"><br>
    <input type="submit" value="Enviar">
</form>

<a href="?id=1' OR '1'='1">Ver todos os usuários (SQLi)</a><br>
<a href="?q=<script>alert('XSS')</script>">Pesquisar (XSS Get)</a><br>
<a href="?cmd=/etc/passwd">Executar comando (System)</a><br>
<a href="?page=../../../../etc/passwd">Incluir arquivo (LFI)</a><br>
<a href="?account_id=999">Acessar conta (IDOR)</a><br>