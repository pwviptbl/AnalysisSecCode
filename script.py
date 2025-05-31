import os
import sys
from datetime import datetime

# Importa as classes que criamos
from config import Configuracao
from analyzers.detector import DetectorVulnerabilidade
from analyzers.vulnerability import Vulnerabilidade
from report_generator import GeradorRelatorio 

# Função para coletar arquivos PHP de um caminho (arquivo ou diretório)
def collect_php_files_from_path(path: str) -> list[str]:
    php_files = []
    if os.path.isfile(path) and path.lower().endswith('.php'):
        # Se o caminho for um arquivo PHP, adiciona ele mesmo
        php_files.append(path)
    elif os.path.isdir(path):
        # Se o caminho for um diretório, percorre ele e adiciona todos os arquivos PHP
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.php'):
                    php_files.append(os.path.join(root, file))
    return php_files


class AnalisadorEstatico:
    """
    Orquestra o processo de análise estática de código PHP,
    detectando vulnerabilidades e gerando relatórios.
    """
    def __init__(self, vul_config_path: str, diretorio_saida: str = "report"):
        self.configuracao = Configuracao(vul_config_path)
        self.detector = DetectorVulnerabilidade(self.configuracao)
        self.relatorio = GeradorRelatorio (diretorio_saida)
        self.diretorio_saida = diretorio_saida

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

        vulnerabilidades_encontradas = self.detector.analyze_php_code(php_code, file_path)

        if vulnerabilidades_encontradas:
            print(f"Vulnerabilidades encontradas em {file_path}:")
            for vul in vulnerabilidades_encontradas:
                self.relatorio.adicionar_vulnerabilidade(vul)
                print(f"- {vul.type} na linha {vul.line} do arquivo: {os.path.basename(vul.file_path)} (Severidade: {vul.severity})")
        else:
            print(f"Nenhuma vulnerabilidade encontrada em {file_path}.")

    def analisar_multiplos_arquivos_php(self, file_paths: list, generate_reports: bool = True) -> list:
        """
        Analisa uma lista de arquivos PHP em busca de vulnerabilidades.
        Se generate_reports for True, gera os relatórios HTML/PDF.
        Retorna a lista de todas as vulnerabilidades encontradas.
        """
        self.relatorio.vulnerabilities = []
        
        if not file_paths:
            print("Nenhum arquivo para analisar. Abortando.")
            return []

        for file_path in file_paths:
            self.analisar_arquivo_php(file_path)
        
        if generate_reports and self.relatorio.get_vulnerabilities():
            self._gerar_relatorios_finais()
        elif not self.relatorio.get_vulnerabilities():
            print("Nenhuma vulnerabilidade encontrada. Relatórios não gerados.")
        else:
            print("Opção 'gerar relatórios' desativada. Relatórios não gerados.")

        return self.relatorio.get_vulnerabilities()


    def _gerar_relatorios_finais(self):
        """
        Gera os relatórios HTML e PDF com todas as vulnerabilidades coletadas.
        """
        print("\nGerando relatórios...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name_base = f"analise_seguranca_{timestamp}"

        self.relatorio.gerar_html(f"{report_name_base}.html")
        self.relatorio.gerar_pdf(f"{report_name_base}.pdf")
        print(f"Relatórios gerados com sucesso na pasta: {self.relatorio.diretorio_saida}")


# Bloco de execução principal (interface de linha de comando ou CI/CD)
if __name__ == "__main__":
    vul_config_json_path = os.path.join(os.path.dirname(__file__), 'Vul', 'php_vulnerabilities.json')
    output_report_dir = "report"
    analisador = AnalisadorEstatico(vul_config_json_path, diretorio_saida=output_report_dir)

    input_paths_from_cli = []
    generate_reports_final = True

    # Processar argumentos da linha de comando
    if len(sys.argv) > 1:
        if "--no-report" in sys.argv:
            generate_reports_final = False
            sys.argv.remove("--no-report")

        input_paths_from_cli = sys.argv[1:] # Pega todos os argumentos restantes
        
        if not input_paths_from_cli: # Se não houver caminhos após remover --no-report
            print("Erro: Nenhum arquivo ou diretório para analisar fornecido.")
            print("Uso: python script.py <caminho_do_arquivo_ou_diretorio> [outro_caminho...] [--no-report]")
            sys.exit(1) # Sai com erro se nao houver caminhos

        # Coleta todos os arquivos PHP dos caminhos fornecidos (arquivos ou diretórios)
        actual_files_to_analyze = []
        for p in input_paths_from_cli:
            if not os.path.exists(p):
                print(f"Aviso: Caminho '{p}' não encontrado. Ignorando.", file=sys.stderr)
                continue
            collected = collect_php_files_from_path(p)
            if not collected:
                print(f"Aviso: Nenhum arquivo PHP encontrado em '{p}'. Ignorando.", file=sys.stderr)
            actual_files_to_analyze.extend(collected)
        
        if not actual_files_to_analyze:
            print("Erro: Nenhum arquivo PHP válido encontrado para análise nos caminhos fornecidos. Abortando.")
            print("Uso: python script.py <caminho_do_arquivo_ou_diretorio> [outro_caminho...] [--no-report]")
            sys.exit(1) # Sai com erro se nao encontrar arquivos PHP

        print(f"Modo de linha de comando: Analisando {len(actual_files_to_analyze)} arquivo(s).")
        analisador.analisar_multiplos_arquivos_php(actual_files_to_analyze, generate_reports=generate_reports_final)
    else:
        # Se não houver argumentos na linha de comando, exibe o uso e sai
        print("Uso: python script.py <caminho_do_arquivo_ou_diretorio> [outro_caminho...] [--no-report]")
        print("Nenhum arquivo ou diretório para análise fornecido. Abortando.")
        sys.exit(1) # Sai com erro

    print("\nAnálise concluída.")