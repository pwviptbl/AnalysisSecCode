import os
from typing import List
from analyzers.vulnerability import Vulnerability # Importa a classe Vulnerability

# Para geração de HTML e PDF, você precisaria instalar Jinja2 e ReportLab:
# pip install Jinja2 reportlab

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    print("Aviso: Jinja2 não encontrado. A geração de relatórios HTML não estará disponível.", file=os.sys.stderr)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Aviso: ReportLab não encontrado. A geração de relatórios PDF não estará disponível.", file=os.sys.stderr)


class Relatorio:
    """
    Gerencia e gera relatórios de vulnerabilidades encontradas.
    """
    def __init__(self, output_dir: str = "report"):
        self.vulnerabilities: List[Vulnerability] = []
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True) # Garante que o diretório de saída exista

        # Configuração para Jinja2 (assumindo templates em uma pasta 'templates')
        self.template_env = None
        if JINJA2_AVAILABLE:
            # Caminho para os templates (ex: templates/report_template.html)
            # Pode ser ajustado para ser mais flexível, mas por enquanto, assume pasta 'templates' na raiz
            template_path = os.path.join(os.path.dirname(__file__), 'templates')
            if os.path.exists(template_path):
                self.template_env = Environment(loader=FileSystemLoader(template_path))
            else:
                print(f"Aviso: Pasta de templates '{template_path}' não encontrada. A geração de relatórios HTML pode falhar.", file=os.sys.stderr)


    def adicionar_vulnerabilidade(self, vulnerability: Vulnerability):
        """
        Adiciona uma vulnerabilidade à lista para o relatório.
        """
        self.vulnerabilities.append(vulnerability)

    def get_vulnerabilities(self) -> List[Vulnerability]:
        """
        Retorna a lista de vulnerabilidades adicionadas.
        """
        return self.vulnerabilities

    def gerar_html(self, filename: str = "report.html"):
        """
        Gera o relatório em formato HTML.
        Requer Jinja2 e um template HTML.
        """
        if not JINJA2_AVAILABLE or not self.template_env:
            print("Erro: Jinja2 não está disponível ou o diretório de templates não foi configurado. Não é possível gerar relatório HTML.", file=os.sys.stderr)
            return False

        try:
            template = self.template_env.get_template('report_template.html') # Assumir que temos este template
            
            # Converte objetos Vulnerability para dicionários para facilitar o uso no template Jinja2
            vulnerabilities_data = [v.to_dict() for v in self.vulnerabilities]

            html_content = template.render(vulnerabilities=vulnerabilities_data,
                                           report_title="Relatório de Análise de Vulnerabilidades PHP")

            output_file_path = os.path.join(self.output_dir, filename)
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"Relatório HTML gerado em: {output_file_path}")
            return True
        except Exception as e:
            print(f"Erro ao gerar relatório HTML: {e}", file=os.sys.stderr)
            return False

    def gerar_pdf(self, filename: str = "report.pdf"):
        """
        Gera o relatório em formato PDF.
        Requer ReportLab.
        """
        if not REPORTLAB_AVAILABLE:
            print("Erro: ReportLab não está disponível. Não é possível gerar relatório PDF.", file=os.sys.stderr)
            return False

        try:
            output_file_path = os.path.join(self.output_dir, filename)
            doc = SimpleDocTemplate(output_file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Título
            title_style = ParagraphStyle(
                name='TitleStyle',
                fontSize=24,
                leading=28,
                alignment=TA_CENTER,
                spaceAfter=20,
                fontName='Helvetica-Bold'
            )
            story.append(Paragraph("Relatório de Análise de Vulnerabilidades PHP", title_style))
            story.append(Spacer(1, 0.2 * 10))

            # Resumo (opcional, adicione se tiver um resumo geral)
            # story.append(Paragraph("Resumo da Análise:", styles['h2']))
            # story.append(Paragraph(f"Total de vulnerabilidades encontradas: {len(self.vulnerabilities)}", styles['Normal']))
            # story.append(Spacer(1, 0.2 * 10))

            # Detalhes das Vulnerabilidades
            story.append(Paragraph("Detalhes das Vulnerabilidades Encontradas:", styles['h2']))
            story.append(Spacer(1, 0.2 * 10))

            if not self.vulnerabilities:
                story.append(Paragraph("Nenhuma vulnerabilidade encontrada.", styles['Normal']))
            else:
                for vul in self.vulnerabilities:
                    story.append(Paragraph(f"<b>Tipo:</b> {vul.type}", styles['Normal']))
                    story.append(Paragraph(f"<b>Severidade:</b> <font color='{self._get_severity_color(vul.severity)}'>{vul.severity}</font>", styles['Normal']))
                    story.append(Paragraph(f"<b>Linha:</b> {vul.line}", styles['Normal']))
                    story.append(Paragraph(f"<b>Descrição:</b> {vul.description}", styles['Normal']))
                    story.append(Paragraph(f"<b>Trecho de Código:</b> <code>{vul.code_snippet}</code>", styles['Normal']))
                    story.append(Paragraph(f"<b>Sugestão de Correção:</b> {vul.suggestion}", styles['Normal']))
                    story.append(Spacer(1, 0.2 * 10)) # Espaço entre vulnerabilidades
                    story.append(Paragraph("-" * 50, styles['Normal'])) # Separador visual


            doc.build(story)
            print(f"Relatório PDF gerado em: {output_file_path}")
            return True
        except Exception as e:
            print(f"Erro ao gerar relatório PDF: {e}", file=os.sys.stderr)
            return False

    def _get_severity_color(self, severity: str) -> str:
        """Retorna uma cor HTML baseada na severidade para PDF."""
        severity_map = {
            "Crítica": colors.red,
            "Alta": colors.red,
            "Média": colors.orange,
            "Baixa": colors.blue,
            "Informativa": colors.green,
            "Desconhecida": colors.black
        }
        return severity_map.get(severity, colors.black)


# Exemplo de uso para teste
if __name__ == "__main__":
    # Para testar, vamos criar algumas vulnerabilidades de exemplo
    from analyzers.vulnerability import Vulnerability

    vul1 = Vulnerability(
        vul_type="SQL Injection",
        description="Parâmetro 'id' vulnerável a SQL Injection via $_GET.",
        severity="Alta",
        line=15,
        code_snippet="$query = 'SELECT * FROM users WHERE id = ' . $_GET['id'];",
        suggestion="Use prepared statements com PDO ou MySQLi."
    )
    vul2 = Vulnerability(
        vul_type="Cross-Site Scripting (XSS)",
        description="Saída não sanitizada de dados de usuário.",
        severity="Média",
        line=22,
        code_snippet="echo $_POST['username'];",
        suggestion="Aplique htmlspecialchars() à saída de dados de usuário."
    )
    vul3 = Vulnerability(
        vul_type="Code Injection (eval/exec)",
        description="Uso perigoso da função eval().",
        severity="Crítica",
        line=30,
        code_snippet="eval($input_code);",
        suggestion="Evite usar eval(). Se for necessário, sanitize rigorosamente a entrada."
    )

    # Cria uma instância do Relatorio
    relatorio = Relatorio(output_dir="report_test")
    relatorio.adicionar_vulnerabilidade(vul1)
    relatorio.adicionar_vulnerabilidade(vul2)
    relatorio.adicionar_vulnerabilidade(vul3)

    print("Tentando gerar relatórios...")
    # Tenta gerar HTML (precisa do template)
    relatorio.gerar_html("exemplo_relatorio.html")
    # Tenta gerar PDF
    relatorio.gerar_pdf("exemplo_relatorio.pdf")

    print("\nVerifique a pasta 'report_test' para os arquivos gerados.")