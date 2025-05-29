import os
import sys
from datetime import datetime 
from config import Configuracao
from analyzers.detector import VulnerabilidadeDetector
from analyzers.vulnerability import Vulnerability 
from report_generator import Relatorio 

class AnalisadorEstatico:
    """
    Orquestra o processo de análise estática de código PHP,
    detectando vulnerabilidades e gerando relatórios.
    """
    def __init__(self, vul_config_path: str, output_dir: str = "report"):
        self.configuracao = Configuracao(vul_config_path)
        self.detector = VulnerabilidadeDetector(self.configuracao)
        self.relatorio = Relatorio(output_dir)
        self.output_dir = output_dir

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

    def analisar_multiplos_arquivos_php(self, file_paths: list):
        """
        Analisa uma lista de arquivos PHP em busca de vulnerabilidades.
        """
        self.relatorio.vulnerabilities = []
        for file_path in file_paths:
            self.analisar_arquivo_php(file_path)
        
        self._gerar_relatorios_finais()

    def _gerar_relatorios_finais(self):
        """
        Gera os relatórios HTML e PDF com todas as vulnerabilidades coletadas.
        """
        print("\nGerando relatórios...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name_base = f"analise_seguranca_{timestamp}"
        self.relatorio.gerar_html(f"{report_name_base}.html")
        self.relatorio.gerar_pdf(f"{report_name_base}.pdf")
        print("Relatórios gerados com sucesso!")

if __name__ == "__main__":
    vul_config_json_path = os.path.join(os.path.dirname(__file__), 'Vul', 'php_vulnerabilities.json')
    
    output_report_dir = "report"

    analisador = AnalisadorEstatico(vul_config_json_path, output_dir=output_report_dir)

    if len(sys.argv) > 1:
        file_paths_to_analyze = sys.argv[1:]
        print(f"Modo de linha de comando: Analisando {len(file_paths_to_analyze)} arquivo(s).")
        analisador.analisar_multiplos_arquivos_php(file_paths_to_analyze)
    else:
        print("Modo de teste padrão: Analisando 'test_files/test_vul.php'.")
        test_file_path = os.path.join(os.path.dirname(__file__), 'test_files', 'test_vul.php')
        analisador.analisar_multiplos_arquivos_php([test_file_path])
        
    print("\nAnálise concluída. Verifique a pasta de relatórios.")