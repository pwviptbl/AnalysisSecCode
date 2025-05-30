@echo off
rem Este script simula um pipeline CI/CD para analise de seguranca.

echo =========================================
echo CI/CD Pipeline Simulation - Security Scan
echo =========================================

echo.
echo [STEP 1/3] - Preparando o ambiente (instalando dependencias)...
rem Em um ambiente CI/CD real, voce instalaria suas dependencias aqui:
rem pip install -r requirements.txt
echo Dependencias verificadas/instaladas (simulado).

echo.
echo [STEP 2/3] - Executando a analise estatica de seguranca...
echo Analisando arquivos em test_files/

rem Define o caminho para o seu script principal
set SCRIPT_PATH=script.py
set TEST_FILE_PATH=test_files\test_vul.php

rem Define se o relatorio deve ser gerado ou nao
rem Por padrao, simulamos um ambiente CI/CD que pode nao querer relatorios HTML/PDF persistentes
set GENERATE_REPORTS_FLAG=--no-report
rem Se quiser gerar relatorios sempre, use: set GENERATE_REPORTS_FLAG=

echo Executando: python %SCRIPT_PATH% %TEST_FILE_PATH% %GENERATE_REPORTS_FLAG%
python %SCRIPT_PATH% %TEST_FILE_PATH% %GENERATE_REPORTS_FLAG%

if %errorlevel% neq 0 (
    echo.
    echo [ERRO] - Analise estatica falhou! Codigo de saida: %errorlevel%
    echo =========================================
    goto :end_script_error
)

echo.
echo [STEP 3/3] - Verificando resultados e artefatos...
echo O script.py ja exibe os resultados no console e pode gerar relatorios.
echo Se relatorios foram gerados (sem --no-report), eles estao na pasta 'report/'.
echo Estes seriam os "artefatos" do pipeline.

rem Opcional: Abrir o ultimo relatorio HTML gerado (se GENERATE_REPORTS_FLAG nao for --no-report)
rem Se você quiser que ele tente abrir o HTML, descomente as proximas 3 linhas:
rem echo.
rem echo Tentando abrir o relatorio HTML mais recente...
rem start report\analise_seguranca_*.html

echo.
echo =========================================
echo CI/CD Pipeline Simulation - CONCLUIDO COM SUCESSO!
echo =========================================

goto :end_script

:end_script_error
echo.
echo Erro durante a execucao do pipeline.
echo.

:end_script
rem Adiciona uma pausa no final para que o terminal nao feche imediatamente
echo.
echo Pressione qualquer tecla para fechar esta janela...
pause > nul