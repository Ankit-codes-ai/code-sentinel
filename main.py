import sys
import os
import subprocess
import shutil

def run_packager(project_path, output_dir='./code-packager/output', api_key=None):
    import sys
    import importlib.util
    
    if api_key:
        os.environ['GEMINI_API_KEY'] = api_key
        print(f"Debug: Set GEMINI_API_KEY environment variable (length: {len(api_key)})")
    else:
        print("Debug: No API key provided to run_packager")
    
    packager_path = os.path.join(os.path.dirname(__file__), 'code-packager', 'packager.py')
    spec = importlib.util.spec_from_file_location('packager', packager_path)
    if spec is None or spec.loader is None:
        raise ImportError('Could not load packager.py')
    packager = importlib.util.module_from_spec(spec)
    sys.modules['packager'] = packager
    spec.loader.exec_module(packager)
    return packager.run_packager(project_path, output_dir)

def ensure_dependencies():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    install_script = 'install_requirements.bat' if os.name == 'nt' else 'install_requirements.sh'
    script_path = os.path.join(os.path.dirname(__file__), install_script)
    if os.path.isfile(script_path):
        try:
            if os.name == 'nt':
                subprocess.check_call(['cmd', '/c', script_path])
            else:
                if not os.access(script_path, os.X_OK):
                    os.chmod(script_path, 0o755)
                subprocess.check_call(['bash', script_path])
        except Exception as exc:
            print(f"Failed to execute {install_script}: {exc}")
        return
    if not os.path.isfile(requirements_path):
        return

    with open(requirements_path, 'r', encoding='utf-8') as req_file:
        requirements = [line.strip() for line in req_file if line.strip() and not line.startswith('#')]
    import importlib.metadata
    missing_or_conflict = False
    for req in requirements:
        pkg_name = req.split('==')[0] if '==' in req else req.split('>=')[0] if '>=' in req else req
        try:
            version = importlib.metadata.version(pkg_name)
        except importlib.metadata.PackageNotFoundError:
            missing_or_conflict = True
            break
    if not missing_or_conflict:
        return
    try:
        pip_cmd = [sys.executable, '-m', 'pip', 'install', '--prefer-binary', '--use-deprecated=legacy-resolver', '-r', requirements_path]
        subprocess.check_call(pip_cmd)
    except Exception as exc:
        print(f"Failed to install dependencies automatically: {exc}")

def main():
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox
    from tkinter import ttk
    import threading
    import webbrowser
    import api_config

    class ModernButton(tk.Frame):
        def __init__(self, parent, text, command=None, bg_color="#4A90E2", hover_color="#357ABD", 
                     text_color="white", disabled_color="#CCCCCC", state="normal", **kwargs):
            super().__init__(parent, **kwargs)
            self.command = command
            self.bg_color = bg_color
            self.hover_color = hover_color
            self.text_color = text_color
            self.disabled_color = disabled_color
            self.state = state

            self.button_height = 32
            self.font = ("Segoe UI", 9, "bold")

            self.canvas = tk.Canvas(self, height=self.button_height, highlightthickness=0, bd=0)
            self.canvas.pack(fill="both", expand=True)

            self.rect = self.canvas.create_rectangle(0, 0, 0, 0, fill=bg_color, outline="", width=0)
            self.text_item = self.canvas.create_text(0, 0, text=text, fill=text_color, 
                                                   font=self.font, anchor="c")

            self.bind("<Configure>", self.on_configure)
            self.canvas.bind("<Configure>", self.on_configure)
            self.canvas.bind("<Button-1>", self.on_click)
            self.canvas.bind("<Enter>", self.on_enter)
            self.canvas.bind("<Leave>", self.on_leave)

            self.update_appearance()
            
        def on_configure(self, event=None):
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            self.canvas.coords(self.rect, 0, 0, w, h)
            self.canvas.coords(self.text_item, w/2, h/2)
            
        def on_click(self, event):
            if self.state == "normal" and self.command:
                self.command()
                
        def on_enter(self, event):
            if self.state == "normal":
                self.canvas.itemconfig(self.rect, fill=self.hover_color)
                
        def on_leave(self, event):
            if self.state == "normal":
                self.canvas.itemconfig(self.rect, fill=self.bg_color)
            else:
                self.canvas.itemconfig(self.rect, fill=self.disabled_color)
                
        def config(self, **kwargs):
            if "state" in kwargs:
                self.state = kwargs["state"]
                self.update_appearance()
                
        def update_appearance(self):
            if self.state == "disabled":
                self.canvas.itemconfig(self.rect, fill=self.disabled_color)
                self.canvas.itemconfig(self.text_item, fill="#888888")
            else:
                self.canvas.itemconfig(self.rect, fill=self.bg_color)
                self.canvas.itemconfig(self.text_item, fill=self.text_color)

    class MainApp:
        def __init__(self, root):
            self.root = root
            self.root.title("Code Review Tool")
            self.root.geometry("850x600")
            self.root.configure(bg="#F5F5F5")
            
            self.project_dir = tk.StringVar()
            self.gemini_api_key = tk.StringVar()
            self.gemini_api_key.set(api_config.load_api_key())
            
            self.setup_styles()
            self.create_widgets()
            
            if not self.gemini_api_key.get():
                self.root.update()
                self.prompt_for_api_key()
            self.check_initial_artifacts()

        def setup_styles(self):
            self.style = ttk.Style()
            self.style.theme_use('clam')
            
            self.style.configure('Title.TLabel', font=('Segoe UI', 14, 'bold'), 
                               foreground='#2C3E50', background='#F5F5F5')
            self.style.configure('Subtitle.TLabel', font=('Segoe UI', 10), 
                               foreground='#34495E', background='#F5F5F5')
            self.style.configure('Modern.TEntry', fieldbackground='white', 
                               borderwidth=1, relief='solid', font=('Segoe UI', 9))
            self.style.configure('Modern.TFrame', background='#F5F5F5')

        def create_widgets(self):
            main_container = ttk.Frame(self.root, style='Modern.TFrame')
            main_container.pack(fill='both', expand=True, padx=10, pady=10)
            
            header_frame = ttk.Frame(main_container, style='Modern.TFrame')
            header_frame.pack(fill='x', pady=(0, 10))
            
            title_label = ttk.Label(header_frame, text="Code Review Tool", 
                                  style='Title.TLabel')
            title_label.pack(anchor='w')
            
            subtitle_label = ttk.Label(header_frame, 
                                     text="Analyze, visualize, and review your code with AI-powered insights", 
                                     style='Subtitle.TLabel')
            subtitle_label.pack(anchor='w', pady=(2, 0))
            
            canvas = tk.Canvas(main_container, bg='#F5F5F5', highlightthickness=0)
            scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas, style='Modern.TFrame')
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            config_section = self.create_section(scrollable_frame, "Configuration")
            
            dir_frame = ttk.Frame(config_section, style='Modern.TFrame')
            dir_frame.pack(fill='x', pady=(0, 15))
            
            ttk.Label(dir_frame, text="Project Directory", style='Subtitle.TLabel').pack(anchor='w')
            dir_input_frame = ttk.Frame(dir_frame, style='Modern.TFrame')
            dir_input_frame.pack(fill='x', pady=(5, 0))
            
            self.dir_entry = ttk.Entry(dir_input_frame, textvariable=self.project_dir, 
                                     style='Modern.TEntry', font=('Segoe UI', 9))
            self.dir_entry.pack(side='left', fill='x', expand=True, ipady=2)
            
            browse_btn = ModernButton(dir_input_frame, "Browse", command=self.browse_dir,
                                    bg_color="#5DADE2", hover_color="#3498DB")
            browse_btn.pack(side='left', padx=(6, 0), fill='y')
            
            api_frame = ttk.Frame(config_section, style='Modern.TFrame')
            api_frame.pack(fill='x', pady=(0, 15))
            
            ttk.Label(api_frame, text="Gemini API Key", style='Subtitle.TLabel').pack(anchor='w')
            api_input_frame = ttk.Frame(api_frame, style='Modern.TFrame')
            api_input_frame.pack(fill='x', pady=(5, 0))
            
            self.api_entry = ttk.Entry(api_input_frame, textvariable=self.gemini_api_key, 
                                     show="*", style='Modern.TEntry', font=('Segoe UI', 9))
            self.api_entry.pack(side='left', fill='x', expand=True, ipady=2)
            
            api_btn = ModernButton(api_input_frame, "Update", command=self.prompt_for_api_key,
                                 bg_color="#F39C12", hover_color="#E67E22")
            api_btn.pack(side='left', padx=(6, 0), fill='y')

            process_section = self.create_section(scrollable_frame, "Processing")

            step1_frame = self.create_step_frame(process_section, "1", "Code Packaging")
            self.packager_btn = ModernButton(step1_frame, "Run Code Packager", 
                                           command=self.run_packager_thread,
                                           bg_color="#27AE60", hover_color="#229954")
            self.packager_btn.pack(fill='x', pady=(0, 6))
            
            step2_frame = self.create_step_frame(process_section, "2", "Visualization")
            vis_buttons_frame = ttk.Frame(step2_frame, style='Modern.TFrame')
            vis_buttons_frame.pack(fill='x', pady=(0, 6))
            
            self.flowchart_btn = ModernButton(vis_buttons_frame, "Project Flowchart", 
                                            command=self.run_flowchart_thread, state='disabled')
            self.flowchart_btn.pack(side='left', fill='x', expand=True, padx=(0, 3))
            
            self.logic_flowchart_btn = ModernButton(vis_buttons_frame, "Logic Flowchart", 
                                                  command=self.run_logic_flowchart_thread, state='disabled')
            self.logic_flowchart_btn.pack(side='left', fill='x', expand=True, padx=(3, 0))
            
            step3_frame = self.create_step_frame(process_section, "3", "Report Generation")
            self.report_btn = ModernButton(step3_frame, "Generate Reports", 
                                         command=self.run_report_thread, state='disabled',
                                         bg_color="#8E44AD", hover_color="#7D3C98")
            self.report_btn.pack(fill='x', pady=(0, 6))
            
            step4_frame = self.create_step_frame(process_section, "4", "Auto-Remediation")
            self.remediator_btn = ModernButton(step4_frame, "Run Auto Remediator", 
                                             command=self.run_remediator_thread, state='disabled',
                                             bg_color="#E74C3C", hover_color="#C0392B")
            self.remediator_btn.pack(fill='x', pady=(0, 6))
            
            results_section = self.create_section(scrollable_frame, "Results")
            
            pdf_frame = ttk.Frame(results_section, style='Modern.TFrame')
            pdf_frame.pack(fill='x', pady=(0, 6))
            
            ttk.Label(pdf_frame, text="PDF Reports", style='Subtitle.TLabel').pack(anchor='w')
            pdf_buttons_frame = ttk.Frame(pdf_frame, style='Modern.TFrame')
            pdf_buttons_frame.pack(fill='x', pady=(3, 0))
            
            self.open_report_btn = ModernButton(pdf_buttons_frame, "Open Full Report", 
                                              command=self.open_report_pdf, state='disabled',
                                              bg_color="#16A085", hover_color="#138D75")
            self.open_report_btn.pack(side='left', fill='x', expand=True, padx=(0, 3))
            
            self.open_summary_btn = ModernButton(pdf_buttons_frame, "Open Summary", 
                                               command=self.open_summary_pdf, state='disabled',
                                               bg_color="#16A085", hover_color="#138D75")
            self.open_summary_btn.pack(side='left', fill='x', expand=True, padx=(3, 0))
            
            svg_frame = ttk.Frame(results_section, style='Modern.TFrame')
            svg_frame.pack(fill='x', pady=(0, 6))
            
            ttk.Label(svg_frame, text="Visualizations", style='Subtitle.TLabel').pack(anchor='w')
            svg_buttons_frame = ttk.Frame(svg_frame, style='Modern.TFrame')
            svg_buttons_frame.pack(fill='x', pady=(3, 0))
            
            self.open_flowchart_svg_btn = ModernButton(svg_buttons_frame, "Open Project Flowchart", 
                                                     command=self.open_project_svg, state='disabled',
                                                     bg_color="#D35400", hover_color="#BA4A00")
            self.open_flowchart_svg_btn.pack(side='left', fill='x', expand=True, padx=(0, 3))
            
            self.open_logic_svg_btn = ModernButton(svg_buttons_frame, "Open Logic Flowchart", 
                                                 command=self.open_logic_svg, state='disabled',
                                                 bg_color="#D35400", hover_color="#BA4A00")
            self.open_logic_svg_btn.pack(side='left', fill='x', expand=True, padx=(3, 0))
            
            reset_frame = ttk.Frame(results_section, style='Modern.TFrame')
            reset_frame.pack(fill='x', pady=(10, 0))
            
            self.reset_btn = ModernButton(reset_frame, "Reset App (Clear Artifacts)", 
                                        command=self.reset_app, state='disabled',
                                        bg_color="#E74C3C", hover_color="#C0392B")
            self.reset_btn.pack(fill='x')
            
            console_section = self.create_section(scrollable_frame, "Console Output")
            
            console_frame = tk.Frame(console_section, bg='#2C3E50', relief='flat', bd=1)
            console_frame.pack(fill='both', expand=True, pady=(0, 6))

            self.console = scrolledtext.ScrolledText(console_frame, height=8, state='disabled',
                                                   bg='#2C3E50', fg='#ECF0F1', 
                                                   insertbackground='#ECF0F1',
                                                   font=('Consolas', 9),
                                                   wrap=tk.WORD, relief='flat', bd=0)
            self.console.pack(fill='both', expand=True, padx=6, pady=6)
            
            self.update_reset_button_state()
            
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def create_section(self, parent, title):
            section_frame = tk.Frame(parent, bg='white', relief='solid', bd=1)
            section_frame.pack(fill='x', pady=(0, 12))

            header = tk.Frame(section_frame, bg='#34495E', height=28)
            header.pack(fill='x')
            header.pack_propagate(False)

            title_label = tk.Label(header, text=title, fg='white', bg='#34495E',
                                 font=('Segoe UI', 10, 'bold'))
            title_label.pack(side='left', padx=10, pady=4)

            content = tk.Frame(section_frame, bg='white')
            content.pack(fill='both', expand=True, padx=10, pady=10)

            return content

        def create_step_frame(self, parent, step_num, title):
            step_frame = tk.Frame(parent, bg='#F8F9FA', relief='solid', bd=1)
            step_frame.pack(fill='x', pady=(0, 8))

            header = tk.Frame(step_frame, bg='#F8F9FA')
            header.pack(fill='x', padx=8, pady=(6, 2))

            step_label = tk.Label(header, text=f"Step {step_num}", fg='#6C757D', 
                                bg='#F8F9FA', font=('Segoe UI', 8, 'bold'))
            step_label.pack(side='left')

            title_label = tk.Label(header, text=title, fg='#495057', 
                                 bg='#F8F9FA', font=('Segoe UI', 9, 'bold'))
            title_label.pack(side='left', padx=(6, 0))

            content = tk.Frame(step_frame, bg='#F8F9FA')
            content.pack(fill='x', padx=8, pady=(0, 8))

            return content

        def update_reset_button_state(self):
            """Enable or disable the reset button based on whether there are artifacts to clear."""
            artifacts = self._detect_artifacts()
            if any(artifacts.values()):
                self.reset_btn.config(state='normal')
            else:
                self.reset_btn.config(state='disabled')

        def prompt_for_api_key(self):
            api_key = api_config.prompt_for_api_key(self.root)
            if api_key:
                self.gemini_api_key.set(api_key)

        def browse_dir(self):
            directory = filedialog.askdirectory()
            if directory:
                self.project_dir.set(directory)

        def run_packager_thread(self):
            if not self.validate_api_key():
                return
            self.packager_btn.config(state='disabled')
            self.console_clear()
            threading.Thread(target=self.run_packager, daemon=True).start()

        def _detect_artifacts(self):
            """Return a dict of booleans indicating presence of key artifacts."""
            base = os.path.dirname(__file__)
            def exists(*parts):
                return os.path.exists(os.path.join(base, *parts))

            return {
                'packager_output': exists('code-packager', 'output', 'subtrees.json'),
                'flowchart_svg': exists('visualizer', 'project_flowchart.svg'),
                'logic_flowchart_svg': exists('visualizer', 'logic_flowchart.svg'),
                'logic_flowchart_mmd_backup': exists('visualizer', 'logic_flowchart.mmd.backup'),
                'report_pdf': exists('review-caller', 'code_review_report.pdf'),
                'summary_pdf': exists('review-caller', 'code_review_summary.pdf'),
                'config_json': exists('config.json'),
            }

        def check_initial_artifacts(self):
            from tkinter import messagebox
            artifacts = self._detect_artifacts()
            artifact_keys = set(k for k, v in artifacts.items() if v)
            if not artifact_keys:
                return
            if artifact_keys == {'config_json'}:
                return

            restore = messagebox.askyesno(
                "Restore Previous Session",
                "Generated artifacts from a previous session were detected. Would you like to restore the UI state so you can view or continue working with them?"
            )
            if restore:
                self.restore_state(artifacts)

        def restore_state(self, artifacts_dict):
            """Enable UI controls based on which artifacts exist."""
            if artifacts_dict.get('packager_output'):
                self.flowchart_btn.config(state='normal')
                self.logic_flowchart_btn.config(state='normal')
                self.report_btn.config(state='normal')

            if artifacts_dict.get('report_pdf'):
                self.open_report_btn.config(state='normal')
            if artifacts_dict.get('summary_pdf'):
                self.open_summary_btn.config(state='normal')

            if artifacts_dict.get('report_pdf') or artifacts_dict.get('summary_pdf'):
                self.remediator_btn.config(state='normal')

            if artifacts_dict.get('flowchart_svg'):
                self.open_flowchart_svg_btn.config(state='normal')
            if artifacts_dict.get('logic_flowchart_svg'):
                self.open_logic_svg_btn.config(state='normal')

            self.update_reset_button_state()
            self.console_write("Previous session artifacts detected. UI state restored.\n")

        def open_project_svg(self):
            svg_path = os.path.join(os.path.dirname(__file__), 'visualizer', 'project_flowchart.svg')
            if os.path.exists(svg_path):
                import webbrowser
                webbrowser.open(svg_path)
            else:
                self.console_write("project_flowchart.svg not found.\n")

        def open_logic_svg(self):
            svg_path = os.path.join(os.path.dirname(__file__), 'visualizer', 'logic_flowchart.svg')
            if not os.path.exists(svg_path):
                base, ext = os.path.splitext(svg_path)
                for idx in range(1, 10):
                    alt = f"{base}_part{idx}{ext}"
                    if os.path.exists(alt):
                        svg_path = alt
                        break
            if os.path.exists(svg_path):
                import webbrowser
                webbrowser.open(svg_path)
            else:
                self.console_write("logic_flowchart.svg not found.\n")

        def validate_api_key(self):
            api_key = self.gemini_api_key.get().strip()
            if not api_key:
                messagebox.showerror("API Key Required", "Please enter a Gemini API key to continue.")
                return False
                
            if not api_config.is_valid_api_key(api_key):
                messagebox.showerror("Invalid API Key", "The API key format appears to be invalid. Google API keys typically start with 'AIza' followed by 35 characters.")
                return False
            api_config.save_api_key(api_key)
            return True

        def run_packager(self):
            project_path = self.project_dir.get()
            if not project_path:
                self.console_write("Please select a project directory.\n")
                self.packager_btn.config(state='normal')
                return
            self.console_write(f"Running code packager on: {project_path}\n")
            try:
                old_stdout = sys.stdout
                sys.stdout = self
                result = run_packager(project_path, api_key=self.gemini_api_key.get())
                sys.stdout = old_stdout
                if result.get('error'):
                    self.console_write(f"Error: {result['error']}\n")
                    self.flowchart_btn.config(state='disabled')
                    self.logic_flowchart_btn.config(state='disabled')
                    self.report_btn.config(state='disabled')
                else:
                    self.console_write("Packaging complete!\n")
                    self.flowchart_btn.config(state='normal')
                    self.logic_flowchart_btn.config(state='normal')
                    self.report_btn.config(state='normal')
            except Exception as e:
                self.console_write(f"Exception: {e}\n")
                self.flowchart_btn.config(state='disabled')
                self.logic_flowchart_btn.config(state='disabled')
                self.report_btn.config(state='disabled')
            self.packager_btn.config(state='normal')

        def write(self, msg):
            self.console_write(msg)
        def flush(self):
            pass
        def console_write(self, msg):
            self.console.config(state='normal')
            self.console.insert('end', msg)
            self.console.see('end')
            self.console.config(state='disabled')
        def console_clear(self):
            self.console.config(state='normal')
            self.console.delete('1.0', 'end')
            self.console.config(state='disabled')

        def run_flowchart_thread(self):
            if not self.validate_api_key():
                return
            if not is_online():
                self.console_write("Cannot run flowchart generator: No Internet connection.\n")
                return
            self.flowchart_btn.config(state='disabled')
            self.logic_flowchart_btn.config(state='disabled')
            self.report_btn.config(state='disabled')
            self.console_write("Running flowchart generator...\n")
            threading.Thread(target=self.run_flowchart, daemon=True).start()

        def run_flowchart(self):
            try:
                script = os.path.join(os.path.dirname(__file__), 'visualizer', 'flowchart-generator.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                result = subprocess.run([sys.executable, script], capture_output=True, text=True, env=env)
                self.console_write(result.stdout)
                if result.stderr:
                    self.console_write(result.stderr)
                self.console_write("Flowchart generation complete!\n")
                mmd_cli = os.path.join(os.path.dirname(__file__), 'visualizer', 'mmd-cli.py')
                struct_mmd = os.path.join(os.path.dirname(__file__), 'visualizer', 'project_flowchart.mmd')
                struct_svg = os.path.join(os.path.dirname(__file__), 'visualizer', 'project_flowchart.svg')
                mmd_result = subprocess.run([sys.executable, mmd_cli, '-i', struct_mmd, '-o', struct_svg], capture_output=True, text=True)
                self.console_write(mmd_result.stdout)
                if mmd_result.stderr:
                    self.console_write(mmd_result.stderr)
                svg_path = struct_svg
                if os.path.exists(svg_path):
                    self.console_write("SVG generated from Mermaid file. Opening in browser...\n")
                    webbrowser.open(svg_path)
                    self.open_flowchart_svg_btn.config(state='normal')
                else:
                    self.console_write("Could not locate SVG file.\n")
            except Exception as e:
                self.console_write(f"Exception: {e}\n")
            self.flowchart_btn.config(state='normal')
            self.logic_flowchart_btn.config(state='normal')
            self.report_btn.config(state='normal')

        def run_report_thread(self):
            if not self.validate_api_key():
                return
            if not is_online():
                self.console_write("Cannot run report generator: No Internet connection.\n")
                return
            self.flowchart_btn.config(state='disabled')
            self.logic_flowchart_btn.config(state='disabled')
            self.report_btn.config(state='disabled')
            self.console_write("Running report generator...\n")
            threading.Thread(target=self.run_report, daemon=True).start()

        def run_report(self):
            try:
                review_script = os.path.join(os.path.dirname(__file__), 'review-caller', 'review-caller.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                result1 = subprocess.run([sys.executable, review_script], capture_output=True, text=True, env=env)
                self.console_write(result1.stdout)
                if result1.stderr:
                    self.console_write(result1.stderr)
                streamlit_script = os.path.join(os.path.dirname(__file__), 'review-caller', 'streamlit-report-viewer.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                env['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
                subprocess.Popen([sys.executable, '-m', 'streamlit', 'run', streamlit_script], env=env)
                self.console_write("Streamlit report viewer launched in browser.\n")
                report_script = os.path.join(os.path.dirname(__file__), 'review-caller', 'report-generator.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                result2 = subprocess.run([sys.executable, report_script], capture_output=True, text=True, env=env)
                self.console_write(result2.stdout)
                if result2.stderr:
                    self.console_write(result2.stderr)
                self.console_write("Report generation complete!\n")

                self.remediator_btn.config(state='normal')

                self.open_report_btn.config(state='normal')
                self.open_summary_btn.config(state='normal')
            except Exception as e:
                self.console_write(f"Exception: {e}\n")
            self.flowchart_btn.config(state='normal')
            self.logic_flowchart_btn.config(state='normal')
            self.report_btn.config(state='normal')

        def open_report_pdf(self):
            pdf_path = os.path.join(os.path.dirname(__file__), 'review-caller', 'code_review_report.pdf')
            try:
                os.startfile(pdf_path)
            except Exception as e:
                messagebox.showerror("Error", f"Could not open PDF: {e}")

        def open_summary_pdf(self):
            pdf_path = os.path.join(os.path.dirname(__file__), 'review-caller', 'code_review_summary.pdf')
            try:
                os.startfile(pdf_path)
            except Exception as e:
                messagebox.showerror("Error", f"Could not open PDF: {e}")

        def run_remediator_thread(self):
            if not self.validate_api_key():
                return
            if not is_online():
                self.console_write("Cannot run auto-remediator: No Internet connection.\n")
                return
            self.remediator_btn.config(state='disabled')
            self.console_write("Running auto-remediator...\n")
            threading.Thread(target=self.run_remediator, daemon=True).start()

        def run_remediator(self):
            try:
                project_path = self.project_dir.get()
                remediator_script = os.path.join(os.path.dirname(__file__), 'auto-remediator', 'remediator.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                result = subprocess.run([sys.executable, remediator_script, '--project-dir', project_path], capture_output=True, text=True, env=env)
                self.console_write(result.stdout)
                if result.stderr:
                    self.console_write(result.stderr)
                self.console_write("Auto-remediation complete!\n")
            except Exception as e:
                self.console_write(f"Remediator exception: {e}\n")
            finally:
                self.remediator_btn.config(state='normal')

        def run_logic_flowchart_thread(self):
            if not self.validate_api_key():
                return
            if not is_online():
                self.console_write("Cannot run logical flowchart generator: No Internet connection.\n")
                return
            self.logic_flowchart_btn.config(state='disabled')
            self.flowchart_btn.config(state='disabled')
            self.report_btn.config(state='disabled')
            self.console_write("Running logical flowchart generator...\n")
            threading.Thread(target=self.run_logic_flowchart, daemon=True).start()

        def run_logic_flowchart(self):
            try:
                script = os.path.join(os.path.dirname(__file__), 'visualizer', 'logic-flowchart.py')
                env = os.environ.copy()
                env['GEMINI_API_KEY'] = self.gemini_api_key.get()
                result = subprocess.run([sys.executable, script], capture_output=True, text=True, env=env)
                self.console_write(result.stdout)
                if result.stderr:
                    self.console_write(result.stderr)
                self.console_write("Logical flowchart generation complete!\n")
                logic_mmd = os.path.join(os.path.dirname(__file__), 'visualizer', 'logic_flowchart.mmd')
                logic_svg = os.path.join(os.path.dirname(__file__), 'visualizer', 'logic_flowchart.svg')
                if os.path.exists(logic_mmd):
                    mmd_cli = os.path.join(os.path.dirname(__file__), 'visualizer', 'mmd-cli.py')
                    mmd_cmd = [
                        sys.executable, mmd_cli,
                        '-i', logic_mmd,
                        '-o', logic_svg,
                        '--fix',
                        '--split-large'
                    ]
                    mmd_result = subprocess.run(mmd_cmd, capture_output=True, text=True)
                    self.console_write(mmd_result.stdout)
                    if mmd_result.stderr:
                        self.console_write(mmd_result.stderr)
                else:
                    self.console_write("Logical .mmd file not found. Skipping SVG generation.\n")
                svg_path = logic_svg
                if not os.path.exists(svg_path):
                    base, ext = os.path.splitext(logic_svg)
                    for idx in range(1, 10):
                        alt_path = f"{base}_part{idx}{ext}"
                        if os.path.exists(alt_path):
                            svg_path = alt_path
                            break

                if os.path.exists(svg_path):
                    self.console_write(f"SVG generated: {svg_path}. Opening in browser...\n")
                    webbrowser.open(svg_path)
                    self.open_logic_svg_btn.config(state='normal')
                else:
                    self.console_write("Could not locate SVG file (including split parts).\n")
            except Exception as e:
                self.console_write(f"Exception: {e}\n")
            self.logic_flowchart_btn.config(state='normal')
            self.flowchart_btn.config(state='normal')
            self.report_btn.config(state='normal')

        def reset_app(self):
            """Remove generated files and directories to return app to a clean state."""
            import tkinter as tk
            from tkinter import messagebox

            confirm = messagebox.askyesno("Confirm Reset", "This will delete generated diagrams, reports, cached data, and config.json. Continue?")
            if not confirm:
                return

            base = os.path.dirname(__file__)

            file_targets = [
                ("visualizer", "project_flowchart.mmd"),
                ("visualizer", "project_flowchart.svg"),
                ("visualizer", "logic_flowchart.svg"),
                ("visualizer", "logic_flowchart.mmd"),
                ("visualizer", "logic_flowchart.mmd.backup"),
                ("visualizer", "mermaid_config.json"),
                ("review-caller", "review_report.json"),
                ("review-caller", "code_review_summary.pdf"),
                ("review-caller", "code_review_report.pdf"),
                ("config.json",),
            ]

            dir_targets = [
                ("code-packager", "output"),
                ("code-packager", "__pycache__"),
                ("__pycache__",),
            ]

            removed_any = False

            for parts in file_targets:
                path = os.path.join(base, *parts)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                        self.console_write(f"Deleted file: {path}\n")
                        removed_any = True
                    except Exception as e:
                        self.console_write(f"Failed to delete {path}: {e}\n")

            for parts in dir_targets:
                path = os.path.join(base, *parts)
                if os.path.isdir(path):
                    try:
                        shutil.rmtree(path)
                        self.console_write(f"Removed directory: {path}\n")
                        removed_any = True
                    except Exception as e:
                        self.console_write(f"Failed to remove directory {path}: {e}\n")

            if removed_any:
                self.console_write("Reset complete.\n")
                self.flowchart_btn.config(state='disabled')
                self.logic_flowchart_btn.config(state='disabled')
                self.report_btn.config(state='disabled')
                self.remediator_btn.config(state='disabled')
                self.open_report_btn.config(state='disabled')
                self.open_summary_btn.config(state='disabled')
                self.open_flowchart_svg_btn.config(state='disabled')
                self.open_logic_svg_btn.config(state='disabled')
            else:
                self.console_write("No artifacts found to delete.\n")
            self.update_reset_button_state()

    def is_online(timeout: int = 3) -> bool:
        from urllib.request import urlopen
        try:
            urlopen('http://www.google.com', timeout=timeout)
            return True
        except Exception:
            return False

    def warn_and_exit_no_internet():
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("No Internet Connection", "This application requires an active Internet connection.\nPlease connect to the Internet and restart.")
        root.destroy()
        sys.exit(1)

    def install_all_dependencies_with_ui():
        import tkinter as tk
        from tkinter import ttk
        import threading
        class _DependencyInstallerWindow:
            def __init__(self, root):
                self.root = root
                self.root.title("Installing Dependencies")
                self.label = tk.Label(root, text="Installing dependencies, please wait...")
                self.label.pack(padx=20, pady=(20, 10))
                self.progress = tk.DoubleVar()
                self.progress_bar = ttk.Progressbar(root, variable=self.progress, maximum=100, mode='indeterminate')
                self.progress_bar.pack(padx=20, pady=(0, 20), fill='x')
                self.progress_bar.start(10)
                self.status = tk.Label(root, text="")
                self.status.pack(padx=20, pady=(0, 20))
                root.update()

            def set_status(self, msg):
                self.status.config(text=msg)
                self.root.update()

            def close(self):
                self.root.destroy()

        dep_root = tk.Tk()
        installer = _DependencyInstallerWindow(dep_root)
        dep_root.update()
        result = {'success': True, 'error_msg': None}

        def do_install():
            try:
                installer.set_status("Running dependency installation script...")
                requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
                install_script = 'install_requirements.bat' if os.name == 'nt' else 'install_requirements.sh'
                script_path = os.path.join(os.path.dirname(__file__), install_script)
                if os.path.isfile(script_path):
                    try:
                        if os.name == 'nt':
                            subprocess.check_call(['cmd', '/c', script_path])
                        else:
                            if not os.access(script_path, os.X_OK):
                                os.chmod(script_path, 0o755)
                            subprocess.check_call(['bash', script_path])
                    except Exception as exc:
                        result['error_msg'] = f"Failed to execute {install_script}: {exc}"
                        result['success'] = False
                else:
                    if os.path.isfile(requirements_path):
                        try:
                            pip_cmd = [sys.executable, '-m', 'pip', 'install', '--prefer-binary', '--use-deprecated=legacy-resolver', '-r', requirements_path]
                            subprocess.check_call(pip_cmd)
                        except Exception as exc:
                            result['error_msg'] = f"Failed to install dependencies automatically: {exc}"
                            result['success'] = False
            finally:
                dep_root.after(0, on_install_done)

        def on_install_done():
            if not result['success']:
                installer.set_status(result['error_msg'] or "Dependency installation failed.")
                dep_root.after(3000, dep_root.destroy)
            else:
                installer.set_status("Dependencies installed successfully!")
                dep_root.after(1000, dep_root.destroy)

        threading.Thread(target=do_install, daemon=True).start()
        dep_root.mainloop()

    if not is_online():
        warn_and_exit_no_internet()
    install_all_dependencies_with_ui()
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()