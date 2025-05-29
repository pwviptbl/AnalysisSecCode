import tkinter as tk
from tkinter import filedialog, messagebox
import os
import threading
import subprocess # Adicionar para abrir pasta no Linux/macOS, se necessário

# Importa a classe AnalisadorEstatico
from script import AnalisadorEstatico

class SecurityAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Analisador de Vulnerabilidades PHP")
        master.geometry("800x600")

        # Configurações iniciais do AnalisadorEstático
        vul_config_json_path = os.path.join(os.path.dirname(__file__), 'Vul', 'php_vulnerabilities.json')
        output_report_dir = "report"

        try:
            self.analyzer = AnalisadorEstatico(vul_config_json_path, output_dir=output_report_dir)
        except Exception as e:
            messagebox.showerror("Erro de Inicialização", f"Não foi possível inicializar o analisador: {e}")
            master.destroy()
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

        # Criar um Text widget com Scrollbar para o log
        self.text_output_frame = tk.Frame(self.middle_frame)
        self.text_output_frame.pack(fill=tk.BOTH, expand=True)

        self.text_output = tk.Text(self.text_output_frame, wrap=tk.WORD, height=15, width=80, state=tk.DISABLED)
        self.text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(self.text_output_frame, command=self.text_output.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_output.config(yscrollcommand=self.scrollbar.set)

        # --- Checkbox para gerar relatórios (NOVO) ---
        self.generate_reports_var = tk.BooleanVar(value=True) # Valor padrão: gerar relatórios
        self.chk_generate_reports = tk.Checkbutton(self.bottom_frame, text="Gerar Relatórios (HTML/PDF)", variable=self.generate_reports_var)
        self.chk_generate_reports.pack(side=tk.LEFT, padx=5)

        # --- Widgets no bottom_frame (Botões de Ação) ---
        self.btn_analyze = tk.Button(self.bottom_frame, text="Iniciar Análise", command=self.start_analysis_thread, bg="green", fg="white")
        self.btn_analyze.pack(side=tk.LEFT, padx=5)

        self.btn_open_reports = tk.Button(self.bottom_frame, text="Abrir Relatórios", command=self.open_reports_folder, state=tk.DISABLED)
        self.btn_open_reports.pack(side=tk.RIGHT, padx=5)

    def _log_message(self, message: str, color: str = "black"):
        """Método auxiliar para adicionar mensagens ao Text widget."""
        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, message + "\n", color)
        self.text_output.see(tk.END) # Auto-scroll
        self.text_output.config(state=tk.DISABLED)
        # Configura as tags de cor
        self.text_output.tag_config("red", foreground="red")
        self.text_output.tag_config("orange", foreground="orange")
        self.text_output.tag_config("green", foreground="green")
        self.text_output.tag_config("blue", foreground="blue")


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
            self.btn_analyze.config(state=tk.NORMAL)

    def clear_files(self):
        self.selected_files = []
        self.listbox_files.delete(0, tk.END)
        self.btn_analyze.config(state=tk.DISABLED)
        self.btn_open_reports.config(state=tk.DISABLED)
        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete(1.0, tk.END)
        self.text_output.config(state=tk.DISABLED)

    def start_analysis_thread(self):
        if not self.selected_files:
            messagebox.showwarning("Nenhum Arquivo", "Por favor, adicione arquivos PHP para análise.")
            return

        self.btn_analyze.config(state=tk.DISABLED, text="Analisando...")
        self.btn_add_files.config(state=tk.DISABLED)
        self.btn_clear_files.config(state=tk.DISABLED)
        self.btn_open_reports.config(state=tk.DISABLED)
        self.chk_generate_reports.config(state=tk.DISABLED) # Desabilita checkbox durante análise

        self.text_output.config(state=tk.NORMAL)
        self.text_output.delete(1.0, tk.END)
        self.text_output.config(state=tk.DISABLED)
        
        self._log_message("Iniciando análise de segurança...\n", "blue") # Cor para mensagem inicial
        
        analysis_thread = threading.Thread(target=self.run_analysis)
        analysis_thread.start()

    def run_analysis(self):
        try:
            self._log_message(f"Analisando {len(self.selected_files)} arquivo(s)...")
            
            # Chama o método de análise da classe AnalisadorEstatico
            # Passa a opção de gerar relatórios
            # A classe AnalisadorEstatico precisa ser modificada para aceitar essa opção
            
            # Alteração temporária para mostrar output no log da GUI
            # Criar um método no AnalisadorEstatico que retorne as vulnerabilidades para o GUI
            # Ou passar uma função de callback para o AnalisadorEstatico
            
            # Opção 1: Fazer o AnalisadorEstatico retornar as vulnerabilidades e GUI processa
            vulnerabilities_found_overall = self.analyzer.analisar_multiplos_arquivos_php(
                self.selected_files,
                generate_reports=self.generate_reports_var.get() # Passa a opção
            )
            
            if vulnerabilities_found_overall:
                self._log_message("\n--- Vulnerabilidades Encontradas ---", "red")
                for vul in vulnerabilities_found_overall:
                    color = "black"
                    if vul.severity == "Crítica" or vul.severity == "Alta":
                        color = "red"
                    elif vul.severity == "Média":
                        color = "orange"
                    elif vul.severity == "Baixa":
                        color = "blue"
                    self._log_message(
                        f"Tipo: {vul.type}\n"
                        f"Arquivo: {os.path.basename(vul.file_path)}\n"
                        f"Linha: {vul.line}\n"
                        f"Severidade: {vul.severity}\n"
                        f"Sugestão: {vul.suggestion}\n"
                        f"Trecho: '{vul.code_snippet}'\n"
                        f"{'-' * 40}", color
                    )
                self._log_message("\nAnálise concluída. Relatórios gerados.", "green")
            else:
                self._log_message("\nNenhuma vulnerabilidade encontrada.", "green")
                self._log_message("Análise concluída. Nenhum relatório gerado pois não há vulnerabilidades.", "green")

        except Exception as e:
            self._log_message(f"Erro durante a análise: {e}", "red")
            messagebox.showerror("Erro de Análise", f"Ocorreu um erro durante a análise: {e}")
        finally:
            self.btn_analyze.config(state=tk.NORMAL, text="Iniciar Análise")
            self.btn_add_files.config(state=tk.NORMAL)
            self.btn_clear_files.config(state=tk.NORMAL)
            self.chk_generate_reports.config(state=tk.NORMAL) # Reabilita checkbox
            self.btn_open_reports.config(state=tk.NORMAL if self.generate_reports_var.get() and vulnerabilities_found_overall else tk.DISABLED) # Ativa se relatórios foram gerados
            
    def open_reports_folder(self):
        report_path = self.analyzer.output_dir
        if os.path.exists(report_path):
            try:
                os.startfile(report_path) # Para Windows
            except AttributeError:
                if os.sys.platform == "darwin":
                    subprocess.Popen(["open", report_path])
                else: # Para Linux
                    subprocess.Popen(["xdg-open", report_path])
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível abrir a pasta de relatórios: {e}")
        else:
            messagebox.showwarning("Pasta não Encontrada", f"A pasta de relatórios '{report_path}' não existe.")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityAnalyzerGUI(root)
    root.mainloop()