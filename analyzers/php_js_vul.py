import sys
import re
import json

def extract_js_from_php(php_code):
    js_code = ""
    in_script = False
    
    for line in php_code.split('\n'):
        if '<script' in line:
            in_script = True
        elif '</script>' in line:
            in_script = False
        elif in_script:
            js_code += line + '\n'
    
    return js_code

def analyze_php(php_code, vulnerabilities):
    results = []
    
    for vul in vulnerabilities:
        pattern = re.compile(vul.get('pattern', ''), re.IGNORECASE)
        for match in pattern.finditer(php_code):
            results.append({
                'vulnerability': vul.get('vulnerability', 'Unknown'),
                'message': vul.get('message', 'No message provided'),
                'line': php_code.count('\n', 0, match.start()) + 1,
                'context': match.group(0)
            })
    
    return results

def analyze_js(js_code, vulnerabilities):
    results = []
    
    for vul in vulnerabilities:
        pattern = re.compile(vul.get('pattern', ''), re.IGNORECASE)
        for match in pattern.finditer(js_code):
            results.append({
                'vulnerability': vul.get('vulnerability', 'Unknown'),
                'message': vul.get('message', 'No message provided'),
                'line': js_code.count('\n', 0, match.start()) + 1,
                'context': match.group(0)
            })
    
    return results

def main():
    if len(sys.argv) != 2:
        print("Uso: python php_js_vul.py <caminho_do_arquivo>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            php_code = file.read()
        
        # Carregar vulnerabilidades PHP
        with open('Vul/php_vulnerabilities.json', 'r') as json_file:
            php_vulnerabilities = json.load(json_file)
        
        # Carregar vulnerabilidades JS
        with open('Vul/js_vulnerabilities.json', 'r') as json_file:
            js_vulnerabilities = json.load(json_file)
        
        # Analisar vulnerabilidades PHP
        php_results = analyze_php(php_code, php_vulnerabilities)
        
        # Extrair e analisar JavaScript
        js_code = extract_js_from_php(php_code)
        js_results = analyze_js(js_code, js_vulnerabilities)
        
        # Gerar relatórios PHP
        php_report_lines = []
        for result in php_results:
            php_report_lines.append(f"Vulnerabilidade: {result['vulnerability']}")
            php_report_lines.append(f"Mensagem: {result['message']}")
            php_report_lines.append(f"Linha: {result['line']}")
            php_report_lines.append(f"Código: {result['context']}")
            php_report_lines.append("="*40)
        
        if not php_results:
            php_report_lines.append("Nenhuma vulnerabilidade encontrada em PHP.")
        
        # Gerar relatórios JS
        js_report_lines = []
        for result in js_results:
            js_report_lines.append(f"Vulnerabilidade: {result['vulnerability']}")
            js_report_lines.append(f"Mensagem: {result['message']}")
            js_report_lines.append(f"Linha: {result['line']}")
            js_report_lines.append(f"Código: {result['context']}")
            js_report_lines.append("="*40)
        
        if not js_results:
            js_report_lines.append("Nenhuma vulnerabilidade encontrada em JavaScript.")
        
        print("\n".join(php_report_lines))
        print("\n".join(js_report_lines))
    
    except FileNotFoundError as e:
        print(f"Arquivo não encontrado: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Erro ao ler o arquivo JSON: {e}")
        sys.exit(1)
    except re.error as e:
        print(f"Erro ao compilar a expressão regular: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
