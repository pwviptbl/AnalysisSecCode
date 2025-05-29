import re
import json
import sys

# Nova Classe: Vulnerabilidade
class Vulnerability:
    """
    Representa uma vulnerabilidade de segurança encontrada no código.
    """
    def __init__(self, vul_type: str, description: str, severity: str,
                 line: int, code_snippet: str, suggestion: str):
        self.type = vul_type
        self.description = description
        self.severity = severity
        self.line = line
        self.code_snippet = code_snippet
        self.suggestion = suggestion

    def __str__(self):
        return (f"Tipo: {self.type}\n"
                f"Descrição: {self.description}\n"
                f"Severidade: {self.severity}\n"
                f"Linha: {self.line}\n"
                f"Trecho de Código: '{self.code_snippet}'\n"
                f"Sugestão: {self.suggestion}")

# Próxima a ser refatorada para classe: VulnerabilidadeDetector
# Por enquanto, manteremos a função analyze_code aqui temporariamente para testes
# e depois a moveremos para dentro da classe VulnerabilidadeDetector.

# Função analyze_code original (será removida ou adaptada em breve)
def analyze_code_old(php_code: str, vulnerabilities_patterns: list):
    results = []
    lines = php_code.splitlines() # Dividir o código em linhas para facilitar a contagem

    for vul in vulnerabilities_patterns:
        pattern_str = vul.get('pattern', '')
        message = vul.get('message', 'Nenhuma mensagem disponível')
        severity = vul.get('severity', 'Desconhecida')
        suggestion = vul.get('suggestion', 'Consulte a documentação de segurança para correção.') # Adicionar sugestão

        try:
            pattern = re.compile(pattern_str)
        except re.error as e:
            print(f"Erro ao compilar a expressão regular '{pattern_str}': {e}", file=sys.stderr)
            continue

        for i, line_content in enumerate(lines):
            for match in pattern.finditer(line_content):
                # A linha de ocorrência é (índice da linha + 1)
                line_number = i + 1
                
                # Contexto: pegar um trecho da linha completa
                context = line_content.strip()

                results.append(Vulnerability(
                    vul_type=vul.get('vulnerability', 'Desconhecida'),
                    description=message,
                    severity=severity,
                    line=line_number,
                    code_snippet=context, # Usar a linha completa como snippet inicial
                    suggestion=suggestion
                ))
    return results

# O bloco main() original também será modificado em breve
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python php_vul.py <caminho_do_arquivo>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            php_code = file.read()
    except FileNotFoundError:
        print(f"Erro: Arquivo '{file_path}' não encontrado.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Erro ao ler o arquivo '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

    try:
        # Caminho do JSON de vulnerabilidades deve ser relativo ao script.py ou analyzers/php_vul.py
        # Para testar este script isoladamente, assumimos que 'Vul' está no mesmo nível
        # ou ajustamos o caminho. Por enquanto, mantemos como estava, mas no AnalisadorEstatico
        # o caminho será passado.
        vulnerabilities_json_path = '../Vul/php_vulnerabilities.json' # Ajuste o caminho se necessário para teste local
        with open(vulnerabilities_json_path, 'r', encoding='utf-8') as file:
            vulnerabilities_data = json.load(file)
    except FileNotFoundError:
        print(f"Erro: Arquivo de padrões de vulnerabilidades '{vulnerabilities_json_path}' não encontrado.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Erro: O arquivo '{vulnerabilities_json_path}' não é um JSON válido.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Erro ao carregar padrões de vulnerabilidades: {e}", file=sys.stderr)
        sys.exit(1)

    results = analyze_code_old(php_code, vulnerabilities_data)

    if results:
        for result in results:
            print(result) # Usando o __str__ da classe Vulnerability
            print("-" * 30)
    else:
        print("Nenhuma vulnerabilidade encontrada.")