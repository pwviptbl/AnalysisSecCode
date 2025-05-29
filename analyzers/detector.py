import re
import sys

# Importa a classe Configuracao do arquivo config.py no diretório raiz
from config import Configuracao
# Importa a classe Vulnerability do novo arquivo analyzers/vulnerability.py
from analyzers.vulnerability import Vulnerability

class VulnerabilidadeDetector: # Nome da classe mantido para compatibilidade inicial, mas será atualizado
    """
    Detecta vulnerabilidades em código PHP utilizando padrões definidos na configuração.
    """
    def __init__(self, configuracao: Configuracao):
        self.configuracao = configuracao
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict:
        """
        Compila as expressões regulares de todos os padrões de vulnerabilidade
        e as armazena em um dicionário para uso eficiente.
        """
        compiled = {}
        # Usamos get_all_vulnerability_patterns() que retorna uma lista de dicionários
        # cada um com os detalhes da vulnerabilidade.
        for details in self.configuracao.get_all_vulnerability_patterns():
            vul_name = details.get('vulnerability', 'Desconhecida') # Pegar o nome da vulnerabilidade
            pattern_str = details.get('pattern', '')
            if pattern_str:
                try:
                    compiled[vul_name] = re.compile(pattern_str)
                except re.error as e:
                    print(f"Erro ao compilar a expressão regular '{pattern_str}' para '{vul_name}': {e}", file=sys.stderr)
            else:
                print(f"Aviso: Padrão regex não encontrado para a vulnerabilidade '{vul_name}'.", file=sys.stderr)
        return compiled

    def analyze_php_code(self, php_code: str) -> list[Vulnerability]:
        """
        Analisa o código PHP fornecido em busca de vulnerabilidades.
        Retorna uma lista de objetos Vulnerability encontrados.
        """
        found_vulnerabilities = []
        lines = php_code.splitlines()

        for vul_name, compiled_pattern in self.compiled_patterns.items():
            # Obtém os detalhes completos da vulnerabilidade da configuração para mensagem e sugestão
            vul_details = self.configuracao.get_vulnerability_pattern(vul_name)
            
            message = vul_details.get('message', 'Nenhuma mensagem disponível')
            severity = vul_details.get('severity', 'Desconhecida')
            suggestion = vul_details.get('suggestion', 'Consulte a documentação de segurança para correção.')

            for i, line_content in enumerate(lines):
                # Importante: O PlantUML não suporta list[Vulnerability] em type hints diretamente na imagem,
                # mas é boa prática para o código Python.
                for match in compiled_pattern.finditer(line_content):
                    line_number = i + 1
                    code_snippet = line_content.strip() 

                    found_vulnerabilities.append(
                        Vulnerability(
                            vul_type=vul_name, 
                            description=message,
                            severity=severity,
                            line=line_number,
                            code_snippet=code_snippet,
                            suggestion=suggestion
                        )
                    )
        return found_vulnerabilities

# O bloco main() de teste será removido daqui, a orquestração será feita por AnalisadorEstatico em script.py.
# Por enquanto, mantemos um stub ou removemos completamente para evitar duplicação ou confusão.
# Para manter a simplicidade e focar na estrutura de classes, o bloco de teste
# 'if __name__ == "__main__":' que estava em php_vul.py será removido deste arquivo.
# Seu teste agora será feito via script.py.