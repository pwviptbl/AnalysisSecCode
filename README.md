# AnalysisSecCode

## Ferramenta de Análise Estática de Código PHP para Detecção de Vulnerabilidades

Esta ferramenta tem como objetivo o desenvolvimento de um software para análise estática de código fonte em aplicações PHP, com foco na identificação de vulnerabilidades de segurança. A proposta surge da necessidade de apoiar desenvolvedores na detecção precoce de falhas, contribuindo para a melhoria da segurança e da qualidade do software.

## Funcionalidades

* **Detecção de Vulnerabilidades:** Identifica padrões de vulnerabilidades comuns em aplicações PHP, como SQL Injection, XSS, uso de funções perigosas (eval, exec, system, etc.), entre outras.
* **Análise de Múltiplos Arquivos:** Capacidade de analisar um ou mais arquivos PHP, ou um diretório inteiro.
* **Relatórios Detalhados:** Gera relatórios em formato HTML e PDF com a descrição da falha, linha de ocorrência, nível de severidade e sugestões de correção.
* **Modos de Operação:**
    * **Terminal (CLI):** Execução via linha de comando, ideal para automação e integração contínua (CI/CD).
    * **Interface Gráfica (GUI):** Uma interface amigável para seleção de arquivos e visualização de resultados.
    * **Integração CI/CD:** Projetado para ser facilmente integrado em pipelines de desenvolvimento contínuo (CI/CD) para varreduras de segurança automatizadas.

## Como Usar

### 1. Pré-requisitos

Certifique-se de ter o Python 3.x (preferencialmente 3.13, como usado no desenvolvimento) instalado em seu sistema operacional (compatível com GNU/Linux e testado no Linux Mint 21.3).

### 2. Instalação

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/pwviptbl/AnalysisSecCode.git](https://github.com/pwviptbl/AnalysisSecCode.git)
    cd AnalysisSecCode
    ```

2.  **Crie e ative um ambiente virtual (recomendado):**
    ```bash
    python3 -m venv venv
    # No Windows:
    .\venv\Scripts\activate
    # No Linux/macOS:
    source venv/bin/activate
    ```

3.  **Instale as dependências:**
    ```bash
    pip install Jinja2 reportlab
    ```

### 3. Execução da Análise

Você pode usar a ferramenta de duas formas principais: via Terminal (CLI) ou via Interface Gráfica (GUI).

#### 3.1. Via Terminal (CLI)

O modo terminal é ideal para uso em scripts, automação e integração CI/CD.

* **Exemplo: Analisar todos os arquivos PHP na pasta `test_files/` e gerar relatórios:**
    ```bash
    python script.py test_files/
    ```
    *Saída esperada (exemplo parcial):*
    ```
    Iniciando análise de: test_files/test_vul.php
    Vulnerabilidades encontradas em C:\Users\...\AnalysisSecCode\test_files\test_vul.php:
    - SQL Injection na linha 4 do arquivo: test_vul.php (Severidade: Alta)
    - Code Injection (eval/exec) na linha 11 do arquivo: test_vul.php (Severidade: Crítica)
    ...
    Gerando relatórios...
    Relatório HTML gerado em: report\analise_seguranca_20250529_XXXXXX.html
    Relatório PDF gerado em: report\analise_seguranca_20250529_XXXXXX.pdf
    Relatórios gerados com sucesso na pasta: report
    Análise concluída.
    ```

* **Exemplo: Analisar um arquivo específico e NÃO gerar relatórios:**
    ```bash
    python script.py test_files/test_vul.php --no-report
    ```
    *Saída esperada (exemplo parcial):*
    ```
    Iniciando análise de: test_files/test_vul.php
    Vulnerabilidades encontradas em C:\Users\...\AnalysisSecCode\test_files\test_vul.php:
    - SQL Injection na linha 4 do arquivo: test_vul.php (Severidade: Alta)
    ...
    Opção 'gerar relatórios' desativada. Relatórios não gerados.
    Análise concluída.
    ```

* **Analisar múltiplos arquivos/diretórios:**
    ```bash
    python script.py test_files/test_vul.php src/backend/
    ```

#### 3.2. Via Interface Gráfica (GUI)

A interface gráfica permite selecionar arquivos visualmente e iniciar a análise.

* **Para iniciar a GUI:**
    ```bash
    python gui_app.py
    ```
* Na GUI, você poderá:
    * Clicar em "Adicionar Arquivos PHP" para selecionar um ou mais arquivos.
    * Clicar em "Iniciar Análise" para executar o processo.
    * Visualizar o log de análise e as vulnerabilidades encontradas diretamente na tela.
    * Marcar/desmarcar a opção "Gerar Relatórios (HTML/PDF)".
    * Clicar em "Abrir Relatórios" para abrir a pasta onde os relatórios (se gerados) foram salvos.

### 4. Estrutura do Projeto