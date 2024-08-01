import json
import sys
import os

def analyze_js(file_path):
    vulnerabilities = []
    try:
        with open(file_path, 'r') as f:
            code = f.read()
        
        # Lê as vulnerabilidades do arquivo JSON
        vulnerabilities_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Vul', 'js_vulnerabilities.json')
        with open(vulnerabilities_file, 'r') as f:
            vulns = json.load(f)
        
        for vuln in vulns:
            if vuln['pattern'] in code:
                vulnerabilities.append(f"Vulnerabilidade encontrada: {vuln['name']}, Mensagem: {vuln['message']}, Nível: {vuln['severity']}")
        
        if not vulnerabilities:
            vulnerabilities.append("Nenhuma vulnerabilidade detectada.")
        
    except Exception as e:
        log_error(f"Erro ao analisar o código JavaScript: {e}")
        vulnerabilities.append(f"Erro ao analisar o código JavaScript: {e}")
    
    return '\n'.join(vulnerabilities)

def log_error(message):
    error_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'report', 'erro.txt')
    with open(error_path, 'a') as f:
        f.write(message + '\n')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        log_error("Uso: python js_vul.py <caminho_do_arquivo>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    try:
        report = analyze_js(file_path)
        print(report)
    except Exception as e:
        log_error(f"Erro ao executar a análise: {e}")
        print(f"Erro ao executar a análise: {e}", file=sys.stderr)
        sys.exit(1)
