import json
import os
import sys

class Configuracao:
    """
    Gerencia as configurações do analisador estático, incluindo os padrões de vulnerabilidades.
    """
    def __init__(self, vulnerabilities_config_path: str):
        self.vulnerabilities_config_path = vulnerabilities_config_path
        self.patterns = {}  # Dicionário para armazenar os padrões de vulnerabilidades
        self.load_configurations()

    def load_configurations(self):
        """
        Carrega os padrões de vulnerabilidades do arquivo JSON especificado.
        """
        if not os.path.exists(self.vulnerabilities_config_path):
            print(f"Erro: Arquivo de configuração de vulnerabilidades '{self.vulnerabilities_config_path}' não encontrado.", file=sys.stderr)
            sys.exit(1)
        
        try:
            with open(self.vulnerabilities_config_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                # O JSON é uma lista de objetos, transformamos em um dicionário para fácil acesso por tipo/nome da vulnerabilidade
                self.patterns = {item['vulnerability']: item for item in data}
        except json.JSONDecodeError:
            print(f"Erro: O arquivo '{self.vulnerabilities_config_path}' não é um JSON válido.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Erro ao carregar configurações de vulnerabilidades de '{self.vulnerabilities_config_path}': {e}", file=sys.stderr)
            sys.exit(1)

    def get_vulnerability_pattern(self, vulnerability_name: str) -> dict:
        """
        Retorna os detalhes de um padrão de vulnerabilidade pelo seu nome.
        Retorna um dicionário vazio se o padrão não for encontrado.
        """
        return self.patterns.get(vulnerability_name, {})

    def get_all_vulnerability_patterns(self) -> list:
        """
        Retorna todos os padrões de vulnerabilidades carregados como uma lista.
        """
        return list(self.patterns.values())

    # Futuramente, poderíamos adicionar métodos para gerenciar quais tipos de vulnerabilidades
    # estão ativados, conforme o "Menu de Configuração de Análise" do documento. [cite: 26, 27]
    # Por exemplo:
    # def set_active_vulnerability_types(self, types: list):
    #     self.active_types = types
    # def is_type_active(self, vul_type: str):
    #     return vul_type in self.active_types

# Exemplo de uso para teste (pode ser removido depois)
if __name__ == "__main__":
    # Assumindo que 'Vul' está no mesmo nível que 'config.py'
    config_file_path = os.path.join('Vul', 'php_vulnerabilities.json')
    
    # Se você executar este script de dentro de analyzers/, o caminho seria '../Vul/php_vulnerabilities.json'
    # Certifique-se de que o caminho esteja correto para onde você está executando o teste.
    
    config = Configuracao(config_file_path)
    
    print("Configurações carregadas:")
    for vul_name, details in config.patterns.items():
        print(f"- {vul_name}: {details.get('severity', 'N/A')}")
        print(f"  Padrão: {details.get('pattern', 'N/A')}")
        print(f"  Sugestão: {details.get('suggestion', 'N/A')}")
    
    print("\nDetalhes de 'SQL Injection':")
    sql_vul = config.get_vulnerability_pattern('SQL Injection')
    if sql_vul:
        print(f"  Mensagem: {sql_vul.get('message', 'N/A')}")
    else:
        print("  Vulnerabilidade 'SQL Injection' não encontrada.")