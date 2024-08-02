import re
import json
import sys

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
        print("Uso: python js_vul.py <caminho_do_arquivo>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    with open(file_path, 'r') as file:
        js_code = file.read()

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

if __name__ == "__main__":
    main()
