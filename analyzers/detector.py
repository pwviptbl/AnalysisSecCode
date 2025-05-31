import re
import sys
from config import Configuracao
from analyzers.vulnerability import Vulnerability

class DetectorVulnerabilidade:
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
        for details in self.configuracao.get_all_vulnerability_patterns():
            vul_name = details.get('vulnerability', 'Desconhecida') 
            pattern_str = details.get('pattern', '')
            if pattern_str:
                try:
                    compiled[vul_name] = re.compile(pattern_str)
                except re.error as e:
                    print(f"Erro ao compilar a expressão regular '{pattern_str}' para '{vul_name}': {e}", file=sys.stderr)
            else:
                print(f"Aviso: Padrão regex não encontrado para a vulnerabilidade '{vul_name}'.", file=sys.stderr)
        return compiled

    def analyze_php_code(self, php_code: str, file_path: str) -> list[Vulnerability]:
        """
        Analisa o código PHP fornecido em busca de vulnerabilidades.
        Retorna uma lista de objetos Vulnerability encontrados.
        """
        found_vulnerabilities = []
        lines = php_code.splitlines()

        for vul_name, compiled_pattern in self.compiled_patterns.items():
            vul_details = self.configuracao.get_vulnerability_pattern(vul_name)
            
            message = vul_details.get('message', 'Nenhuma mensagem disponível')
            severity = vul_details.get('severity', 'Desconhecida')
            suggestion = vul_details.get('suggestion', 'Consulte a documentação de segurança para correção.')

            for i, line_content in enumerate(lines):
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
                            suggestion=suggestion,
                            file_path=file_path
                        )
                    )
        return found_vulnerabilities