import sys
import re
import json
from bs4 import BeautifulSoup

def extract_js_from_html(html_code):
    soup = BeautifulSoup(html_code, 'html.parser')
    js_code = ""
    
    # Extrair código JavaScript das tags <script>
    for script_tag in soup.find_all('script'):
        js_code += script_tag.string or ""
    
    return js_code

def analyze_code(js_code, vulnerabilities):
    results = []
    for vul in vulnerabilities:
        pattern_str = vul.get('pattern', '')
        try:
            pattern = re.compile(pattern_str)
        except re.error as e:
            print(f"Erro ao compilar a expressão regular '{pattern_str}': {e}", file=sys.stderr)
            continue
        for match in pattern.finditer(js_code):
            results.append({
                'vulnerability': vul.get('vulnerability', 'Desconhecida'),
                'message': vul.get('message', 'Nenhuma mensagem disponível'),
                'severity': vul.get('severity', 'Desconhecida'),
                'line': js_code.count('\n', 0, match.start()) + 1,
                'context': js_code[max(0, match.start() - 30):match.end() + 30]
            })
    return results

def main():

    if len(sys.argv) != 2:
        print("Uso: python html_vul.py <caminho_do_arquivo>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            html_code = file.read()

        js_code = extract_js_from_html(html_code)

        # Carregar vulnerabilidades de JS
        with open('Vul/js_vulnerabilities.json', 'r') as file:
            vulnerabilities = json.load(file)
        
        results = analyze_code(js_code, vulnerabilities)

        for result in results:
            print(f"Vulnerabilidade: {result['vulnerability']}")
            print(f"Mensagem: {result['message']}")
            print(f"Severidade: {result['severity']}")
            print(f"Linha: {result['line']}")
            print(f"Código: {result['context']}")
            print()
    
    except FileNotFoundError as e:
        print(f"Arquivo não encontrado: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Erro ao ler o arquivo JSON: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
