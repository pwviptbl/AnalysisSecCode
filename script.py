import subprocess
import sys
import os

def determine_file_type(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext == '.js':
        return 'js'
    elif ext == '.php':
        return 'php'
    else:
        return None

def run_analysis(file_path, file_type):
    if file_type == 'js':
        script_name = 'analyzers/js_vul.py'
        report_name = 'js_report.txt'
        vulnerabilities_file = 'Vul/js_vulnerabilities.json'
    elif file_type == 'php':
        script_name = 'analyzers/php_vul.py'
        report_name = 'php_report.txt'
        vulnerabilities_file = 'Vul/php_vulnerabilities.json'
    else:
        log_error("Tipo de arquivo não suportado. Use um arquivo com extensão '.js' ou '.php'.")
        return
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(project_root, script_name)
    vulnerabilities_path = os.path.join(project_root, vulnerabilities_file)
    report_path = os.path.join(project_root, 'report', report_name)
    error_path = os.path.join(project_root, 'report', 'erro.txt')
    
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    if not os.path.isfile(vulnerabilities_path):
        log_error(f"Arquivo de vulnerabilidades não encontrado: {vulnerabilities_path}")
        return

    try:
        result = subprocess.run(['python', script_path, file_path], capture_output=True, text=True, check=True)
        report_content = result.stdout
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao executar o script: {e}\nSaída de erro: {e.stderr}")
        report_content = f"Erro ao executar o script: {e}\nSaída de erro: {e.stderr}"
    
    with open(report_path, 'w') as f:
        f.write(f"Relatório gerado para o arquivo: {file_path}\n")
        f.write(report_content)
        f.write("\n")

def log_error(message):
    error_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'report', 'erro.txt')
    with open(error_path, 'a') as f:
        f.write(message + '\n')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        log_error("Uso: python script.py <caminho_do_arquivo>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    file_type = determine_file_type(file_path)
    
    if file_type is None:
        log_error("Tipo de arquivo não suportado. Use um arquivo com extensão '.js' ou '.php'.")
        sys.exit(1)
    
    run_analysis(file_path, file_type)
