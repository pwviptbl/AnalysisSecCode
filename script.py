import subprocess
import os

def run_php_analysis(file_path):
    # Executar a análise de vulnerabilidades PHP
    php_vul_cmd = ['python', 'analyzers/php_vul.py', file_path]
    
    php_vul_result = subprocess.run(php_vul_cmd, capture_output=True, text=True, check=True)

    # # Executar a análise de vulnerabilidades JavaScript dentro do PHP
    php_js_vul_cmd = ['python', 'analyzers/php_js_vul.py', file_path]
    php_js_vul_result = subprocess.run(php_js_vul_cmd, capture_output=True, text=True, check=True)

    return php_vul_result.stdout, php_js_vul_result.stdout

def run_js_analysis(file_path):
    # Executar a análise de vulnerabilidades JavaScript
    js_vul_cmd = ['python', 'analyzers/js_vul.py', file_path]
    js_vul_result = subprocess.run(js_vul_cmd, capture_output=True, text=True, check=True)
    
    return js_vul_result.stdout

def run_html_analysis(file_path):
    # Executar a análise de vulnerabilidades JavaScript dentro do HTML
    html_vul_cmd = ['python', 'analyzers/html_vul.py', file_path]
    html_vul_result = subprocess.run(html_vul_cmd, capture_output=True, text=True, check=True)
    
    return html_vul_result.stdout

def run_analysis(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension == '.php':
        run_php_analysis(file_path)
        php_output, php_js_output = run_php_analysis(file_path)
        #Salvar relatórios PHP
        
        with open('report/php_report.txt', 'w', encoding='utf-8') as php_report:
            php_report.write(php_output)
        # Salvar relatórios JavaScript
        with open('report/js_report.txt', 'w', encoding='utf-8') as js_report:
            js_report.write(php_js_output)
    elif file_extension == '.js':
        js_output = run_js_analysis(file_path)
        with open('report/js_report.txt', 'w', encoding='utf-8') as js_report:
            js_report.write(js_output)
    elif file_extension == '.html':
        html_output = run_html_analysis(file_path)
        with open('report/html_report.txt', 'w', encoding='utf-8') as html_report:
            html_report.write(html_output)
    else:
        print("Extensão de arquivo não suportada.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python script.py <caminho_do_arquivo>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Criar a pasta de relatórios se não existir
    report_path = 'report'
    if not os.path.exists(report_path):
        os.makedirs(report_path)
    
    run_analysis(file_path)
