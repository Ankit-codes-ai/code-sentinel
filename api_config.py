import os
import json
import tkinter as tk
from tkinter import simpledialog, messagebox
import re

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('gemini_api_key', '')
        except Exception as e:
            print(f"Error loading API key: {e}")
    return ''

def save_api_key(api_key):
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except Exception:
            pass
    
    config['gemini_api_key'] = api_key
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        return True
    except Exception as e:
        print(f"Error saving API key: {e}")
        return False

def is_valid_api_key(api_key):
    if not api_key:
        return False
    return bool(re.match(r'^AIza[0-9A-Za-z-_]{35}$', api_key))

def prompt_for_api_key(parent=None):
    current_key = load_api_key()
    
    if parent is None:
        root = tk.Tk()
        root.withdraw()
        parent = root
    class ApiKeyDialog(tk.Toplevel):
        def __init__(self, parent, current_key):
            super().__init__(parent)
            self.title("Gemini API Key Required")
            self.result = None
            self.transient(parent)
            self.protocol("WM_DELETE_WINDOW", self.cancel)
            
            frame = tk.Frame(self, padx=20, pady=10)
            frame.pack(padx=10, pady=10)
            
            msg = "Please enter your Gemini API key.\nThis is required for code review functionality."
            tk.Label(frame, text=msg, justify=tk.LEFT).pack(anchor='w', pady=(0, 10))
            
            tk.Label(frame, text="Get your API key from: https://aistudio.google.com/app/apikey").pack(anchor='w')
            
            entry_frame = tk.Frame(frame)
            entry_frame.pack(fill='x', pady=10)
            tk.Label(entry_frame, text="API Key:").pack(side='left')
            self.entry = tk.Entry(entry_frame, width=50, show="*")
            self.entry.pack(side='left', padx=5, fill='x', expand=True)
            if current_key:
                self.entry.insert(0, current_key)
            
            btn_frame = tk.Frame(frame)
            btn_frame.pack(fill='x', pady=(10, 0))
            tk.Button(btn_frame, text="OK", command=self.ok, width=10).pack(side='right', padx=5)
            tk.Button(btn_frame, text="Cancel", command=self.cancel, width=10).pack(side='right')
            
            self.entry.focus_set()
            self.grab_set()
            
            self.update_idletasks()
            parent_x = parent.winfo_rootx()
            parent_y = parent.winfo_rooty()
            parent_width = parent.winfo_width()
            parent_height = parent.winfo_height()
            width = self.winfo_width()
            height = self.winfo_height()
            x = parent_x + (parent_width // 2) - (width // 2)
            y = parent_y + (parent_height // 2) - (height // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
            
            self.wait_window(self)
            
        def ok(self):
            self.result = self.entry.get().strip()
            if not self.result:
                messagebox.showerror("Error", "API key cannot be empty")
                return
                
            if not is_valid_api_key(self.result):
                messagebox.showerror("Error", "Invalid API key format. Google API keys typically start with 'AIza' followed by 35 characters.")
                return
                
            self.destroy()
            
        def cancel(self):
            self.result = None
            self.destroy()
    
    dialog = ApiKeyDialog(parent, current_key)
    api_key = dialog.result
    
    if api_key:
        save_api_key(api_key)
        return api_key
    
    return None 