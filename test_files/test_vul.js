var user_input = 'alert("xss")';
eval(user_input); // Uso inseguro de eval

document.write('<div>' + user_input + '</div>'); // Manipulação insegura

document.cookie = "username=JohnDoe"; // Possível problema de segurança
// Exemplo de código JavaScript vulnerável
var user_input = document.getElementById('input').value;
eval(user_input); // Esta linha é vulnerável a injeção de código


