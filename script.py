import os
import sys

# Importa as classes que criamos
from config import Configuracao
from analyzers.detector import VulnerabilidadeDetector
from analyzers.vulnerability import Vulnerability # Embora AnalisadorEstatico não crie Vulnerability, ele lida com listas delas
from report_generator import Relatorio # A classe Relatorio

class AnalisadorEstatico:
    """
    Orquestra o processo de análise estática de código PHP,
    detectando vulnerabilidades e gerando relatórios.
    """
    def __init__(self, vul_config_path: str, output_dir: str = "report"):
        self.configuracao = Configuracao(vul_config_path)
        self.detector = VulnerabilidadeDetector(self.configuracao)
        self.relatorio = Relatorio(output_dir)
        self.output_dir = output_dir # Armazena o diretório de saída

    def analisar_arquivo_php(self, file_path: str):
        """
        Analisa um único arquivo PHP em busca de vulnerabilidades.
        """
        if not os.path.exists(file_path):
            print(f"Erro: Arquivo '{file_path}' não encontrado.", file=sys.stderr)
            return

        print(f"Iniciando análise de: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                php_code = file.read()
        except Exception as e:
            print(f"Erro ao ler o arquivo '{file_path}': {e}", file=sys.stderr)
            return

        # Limpa o relatório para esta nova análise (se for analisar um por um)
        # Se for analisar múltiplos arquivos em uma única execução, esta linha pode ser removida
        # e as vulnerabilidades seriam acumuladas no self.relatorio
        # self.relatorio.vulnerabilities = [] # Descomentar se cada chamada analisa apenas um arquivo e reinicia o relatório

        vulnerabilidades_encontradas = self.detector.analyze_php_code(php_code)

        if vulnerabilidades_encontradas:
            print(f"Vulnerabilidades encontradas em {file_path}:")
            for vul in vulnerabilidades_encontradas:
                self.relatorio.adicionar_vulnerabilidade(vul) # Adiciona ao objeto Relatorio
                print(f"- {vul.type} na linha {vul.line} (Severidade: {vul.severity})")
        else:
            print(f"Nenhuma vulnerabilidade encontrada em {file_path}.")

    def analisar_multiplos_arquivos_php(self, file_paths: list):
        """
        Analisa uma lista de arquivos PHP em busca de vulnerabilidades.
        """
        self.relatorio.vulnerabilities = [] # Garante que o relatório esteja limpo para múltiplos arquivos
        for file_path in file_paths:
            self.analisar_arquivo_php(file_path)
        
        # Após analisar todos os arquivos, gerar o relatório final
        self._gerar_relatorios_finais()

    def _gerar_relatorios_finais(self):
        """
        Gera os relatórios HTML e PDF com todas as vulnerabilidades coletadas.
        """
        print("\nGerando relatórios...")
        report_name_base = "analise_seguranca" # Nome base para os arquivos de relatório
        self.relatorio.gerar_html(f"{report_name_base}.html")
        self.relatorio.gerar_pdf(f"{report_name_base}.pdf")
        print("Relatórios gerados com sucesso!")

# Bloco de execução principal (simula a interface de linha de comando ou CI/CD)
if __name__ == "__main__":
    # Caminho do JSON de vulnerabilidades (ajuste conforme a sua estrutura de pastas)
    # Assumindo que 'Vul' está na raiz do projeto
    vul_config_json_path = os.path.join(os.path.dirname(__file__), 'Vul', 'php_vulnerabilities.json')
    
    # Define o diretório de saída dos relatórios
    output_report_dir = "report" # Cria a pasta 'report' na raiz do projeto

    # Cria uma instância do Analisador Estático
    analisador = AnalisadorEstatico(vul_config_json_path, output_dir=output_report_dir)

    # --- SIMULAÇÃO DE USO ---

    if len(sys.argv) > 1:
        # Modo de uso via linha de comando para múltiplos arquivos
        # Ex: python script.py test_files/file1.php test_files/file2.php
        file_paths_to_analyze = sys.argv[1:]
        print(f"Modo de linha de comando: Analisando {len(file_paths_to_analyze)} arquivo(s).")
        analisador.analisar_multiplos_arquivos_php(file_paths_to_analyze)
    else:
        # Modo de teste padrão: Analisa o arquivo de teste_vul.php
        # Ex: python script.py
        print("Modo de teste padrão: Analisando 'test_files/test_vul.php'.")
        test_file_path = os.path.join(os.path.dirname(__file__), 'test_files', 'test_vul.php')
        analisador.analisar_multiplos_arquivos_php([test_file_path])
        
    print("\nAnálise concluída. Verifique a pasta de relatórios.")