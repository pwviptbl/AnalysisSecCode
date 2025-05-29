import tkinter as tk
from tkinter import filedialog, messagebox
import os
import threading # Para executar a análise em uma thread separada e não travar a GUI

# Importa a classe AnalisadorEstatico
from script import AnalisadorEstatico

class SecurityAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Analisador de Vulnerabilidades PHP")
        master.geometry("800x600") # Tamanho inicial da janela

        # Configurações iniciais do AnalisadorEstático
        # Assumindo que 'Vul' está na raiz do projeto
        vul_config_json_path = os.path.join(os.path.dirname(__file__), 'Vul', 'php_vulnerabilities.json')
        output_report_dir = "report" # Pasta de saída para relatórios

        try:
            self.analyzer = AnalisadorEstatico(vul_config_json_path, output_dir=output_report_dir)
        except Exception as e:
            messagebox.showerror("Erro de Inicialização", f"Não foi possível inicializar o analisador: {e}")
            master.destroy() # Fecha a janela se houver erro crítico na inicialização
            return

        self.selected_files = []

        # --- Frames para organização ---
        self.top_frame = tk.Frame(master, padx=10, pady=10)
        self.top_frame.pack(fill=tk.X)

        self.middle_frame = tk.Frame(master, padx=10, pady=10)
        self.middle_frame.pack(fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(master, padx=10, pady=10)
        self.bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # --- Widgets no top_frame (Seleção de Arquivos) ---
        self.label_files = tk.Label(self.top_frame, text="Arquivos Selecionados:")
        self.label_files.pack(anchor=tk.W)

        self.listbox_files = tk.Listbox(self.top_frame, height=5, width=80)
        self.listbox_files.pack(fill=tk.X, pady=5)

        self.btn_add_files = tk.Button(self.top_frame, text="Adicionar Arquivos PHP", command=self.add_files)
        self.btn_add_files.pack(side=tk.LEFT, padx=5)

        self.btn_clear_files = tk.Button(self.top_frame, text="Limpar Lista", command=self.clear_files)
        self.btn_clear_files.pack(side=tk.LEFT, padx=5)
        
        # --- Widgets no middle_frame (Área de Log/Resultados) ---
        self.label_output = tk.Label(self.middle_frame, text="Log de Análise:")
        self.label_output.pack(anchor=tk.W)

        self.text_output = tk.Text(self.middle_frame, wrap=tk.WORD, height=15, width=80, state=tk.DISABLED)
        self.text_output.pack(fill=tk.BOTH, expand=True)

        # --- Widgets no bottom_frame (Botões de Ação) ---
        self.btn_analyze = tk.Button(self.bottom_frame, text="Iniciar Análise", command=self.start_analysis_thread, bg="green", fg="white")
        self.btn_analyze.pack(side=tk.LEFT, padx=5)

        self.btn_open_reports = tk.Button(self.bottom_frame, text="Abrir Relatórios", command=self.open_reports_folder, state=tk.DISABLED)
        self.btn_open_reports.pack(side=tk.RIGHT, padx=5)

    def _log_message(self, message: str):
        """Método auxiliar para adicionar mensagens ao Text widget."""
        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, message + "\n")
        self.text_output.see(tk.END) # Auto-scroll
        self.text_output.config(state=tk.DISABLED)

    def add_files(self):
        files = filedialog.askopenfilenames(
            title="Selecione Arquivos PHP para Análise",
            filetypes=[("Arquivos PHP", "*.php"), ("Todos os Arquivos", "*.*")]
        )
        if files:
            for f in files:
                if f not in self.selected_files:
                    self.selected_files.append(f)
                    self.listbox_files.insert(tk.END, os.path.basename(f))
            self.btn_analyze.config(state=tk.NORMAL) # Ativa o botão de análise

    def clear_files(self):
        self.selected_files = []
        self.listbox_files.delete(0, tk.END)
        self.btn_analyze.config(state=tk.DISABLED) # Desativa o botão de análise
        self.btn_open_reports.config(state=tk.DISABLED) # Desativa o botão de abrir relatórios
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete(1.0, tk.END) # Limpa o log
        self.text_output.config(state=tk.DISABLED)

    def start_analysis_thread(self):
        if not self.selected_files:
            messagebox.showwarning("Nenhum Arquivo", "Por favor, adicione arquivos PHP para análise.")
            return

        self.btn_analyze.config(state=tk.DISABLED, text="Analisando...")
        self.btn_add_files.config(state=tk.DISABLED)
        self.btn_clear_files.config(state=tk.DISABLED)
        self.btn_open_reports.config(state=tk.DISABLED)
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete(1.0, tk.END) # Limpa o log anterior
        self.text_output.config(state=tk.DISABLED)
        
        self._log_message("Iniciando análise de segurança...")
        
        # Executa a análise em uma thread separada para não travar a GUI
        analysis_thread = threading.Thread(target=self.run_analysis)
        analysis_thread.start()

    def run_analysis(self):
        try:
            self._log_message(f"Analisando {len(self.selected_files)} arquivo(s)...")
            self.analyzer.analisar_multiplos_arquivos_php(self.selected_files)
            self._log_message("Análise concluída. Relatórios gerados.")
        except Exception as e:
            self._log_message(f"Erro durante a análise: {e}")
            messagebox.showerror("Erro de Análise", f"Ocorreu um erro durante a análise: {e}")
        finally:
            self.btn_analyze.config(state=tk.NORMAL, text="Iniciar Análise")
            self.btn_add_files.config(state=tk.NORMAL)
            self.btn_clear_files.config(state=tk.NORMAL)
            self.btn_open_reports.config(state=tk.NORMAL) # Ativa o botão de abrir relatórios

    def open_reports_folder(self):
        # Abre a pasta de relatórios no explorador de arquivos do sistema
        report_path = self.analyzer.output_dir # Pega o diretório de saída do analisador
        if os.path.exists(report_path):
            try:
                os.startfile(report_path) # Para Windows
            except AttributeError:
                # Para macOS
                if os.sys.platform == "darwin":
                    subprocess.Popen(["open", report_path])
                # Para Linux
                else:
                    subprocess.Popen(["xdg-open", report_path])
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível abrir a pasta de relatórios: {e}")
        else:
            messagebox.showwarning("Pasta não Encontrada", f"A pasta de relatórios '{report_path}' não existe.")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityAnalyzerGUI(root)
    root.mainloop()