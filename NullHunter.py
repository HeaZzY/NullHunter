#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import json
from pathlib import Path

DARK_BG = "#1e1e1e"
DARKER_BG = "#252526"
DARK_TEXT = "#e0e0e0"
ACCENT_COLOR = "#007acc"
HIGHLIGHT_COLOR = "#264f78"
ERROR_COLOR = "#f44747"
SUCCESS_COLOR = "#6a9955"

class ShellcodeExtractor:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        
    def compile_shellcode(self, asm_file, architecture="elf64"):
        obj_file = os.path.join(self.temp_dir, "shellcode.o")
        
        try:
            result = subprocess.run(
                ["nasm", "-f", architecture, asm_file, "-o", obj_file],
                capture_output=True,
                text=True,
                check=True
            )
            return obj_file
        except subprocess.CalledProcessError as e:
            raise Exception(f"Compilation error: {e.stderr}")
        except FileNotFoundError:
            raise Exception("nasm compiler not found. Please install nasm.")
    
    def extract_shellcode(self, obj_file):
        try:
            result = subprocess.run(
                ["objdump", "-d", obj_file],
                capture_output=True,
                text=True,
                check=True
            )
            
            shellcode_bytes = []
            
            for line in result.stdout.splitlines():
                if line.strip() and ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        hex_part = parts[1].strip().split("\t")[0]
                        hex_part = hex_part.replace(" ", "")
                        for i in range(0, len(hex_part), 2):
                            if i+1 < len(hex_part): 
                                byte = hex_part[i:i+2]
                                if byte: 
                                    shellcode_bytes.append(f"\\x{byte}")
            
            shellcode = "".join(shellcode_bytes)
            
            if not shellcode:
                with open(obj_file, 'rb') as f:
                    binary_content = f.read()
                    

                shellcode_bytes = []
                for byte in binary_content:
                    shellcode_bytes.append(f"\\x{byte:02x}")
                
                # Joindre tous les octets
                shellcode = "".join(shellcode_bytes)
            
            return {
                "parsed": shellcode,
                "raw": shellcode 
            }
        except subprocess.CalledProcessError as e:
            raise Exception(f"Extraction error: {e.stderr}")
        except FileNotFoundError:
            try:
                with open(obj_file, 'rb') as f:
                    binary_content = f.read()
                    
                shellcode_bytes = []
                for byte in binary_content:
                    shellcode_bytes.append(f"\\x{byte:02x}")
                
                # Joindre tous les octets
                shellcode = "".join(shellcode_bytes)
                
                return {
                    "parsed": shellcode,
                    "raw": shellcode
                }
            except Exception as e:
                raise Exception(f"Failed to extract shellcode: {str(e)}")
    
    def process_file(self, asm_file, architecture="elf64"):
        try:
            obj_file = self.compile_shellcode(asm_file, architecture)
            shellcode = self.extract_shellcode(obj_file)
            return shellcode
        except Exception as e:
            raise e
    
    def cleanup(self):
        for file in os.listdir(self.temp_dir):
            file_path = os.path.join(self.temp_dir, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")


class DarkTheme:
    @staticmethod
    def configure_theme(root):
        style = ttk.Style()
        style.theme_use('clam')
        
        root.configure(bg=DARK_BG)
        
        style.configure('TFrame', background=DARK_BG)
        style.configure('TLabel', background=DARK_BG, foreground=DARK_TEXT)
        style.configure('TButton', background=DARKER_BG, foreground=DARK_TEXT)
        style.map('TButton',
            background=[('active', HIGHLIGHT_COLOR), ('pressed', ACCENT_COLOR)],
            foreground=[('active', DARK_TEXT)]
        )
        style.configure('TCombobox', 
            background=DARKER_BG, 
            foreground=DARK_TEXT,
            fieldbackground=DARKER_BG, 
            selectbackground=HIGHLIGHT_COLOR
        )
        style.map('TCombobox',
            background=[('readonly', DARKER_BG)],
            fieldbackground=[('readonly', DARKER_BG)]
        )
        
        style.configure('Treeview', 
            background=DARKER_BG, 
            foreground=DARK_TEXT,
            fieldbackground=DARKER_BG
        )
        style.map('Treeview',
            background=[('selected', HIGHLIGHT_COLOR)],
            foreground=[('selected', DARK_TEXT)]
        )
        
        style.configure('TSeparator', background=ACCENT_COLOR)
        
        style.configure('Statusbar.TLabel', 
            background=DARKER_BG, 
            foreground=DARK_TEXT, 
            padding=3
        )
        
        style.configure('TNotebook', background=DARK_BG)
        style.configure('TNotebook.Tab', 
            background=DARKER_BG, 
            foreground=DARK_TEXT,
            padding=[10, 5]
        )
        style.map('TNotebook.Tab',
            background=[('selected', ACCENT_COLOR)],
            foreground=[('selected', DARK_TEXT)]
        )
        
        return style



class ShellcodeManager:
    def __init__(self, shellcode_dir=None):
        if shellcode_dir is None:
            self.shellcode_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.shellcode_dir = shellcode_dir
            
        # Créer le dossier shellcode s'il n'existe pas
        self.shellcode_folder = os.path.join(self.shellcode_dir, "shellcode")
        if not os.path.exists(self.shellcode_folder):
            os.makedirs(self.shellcode_folder)
        
        # Les catégories correspondent aux dossiers dans "shellcode"
        self.known_dirs = ["Linux 32 bits", "Linux 64 bits", "Linux32Bits", "Linux64Bits"]
        
    def discover_shellcodes(self):
        """Découvre tous les shellcodes disponibles dans les dossiers"""
        shellcodes = []
        
        # Parcourir le répertoire principal des shellcodes
        for root, dirs, files in os.walk(self.shellcode_folder):
            # Tous les dossiers dans le répertoire shellcode sont considérés comme des shellcodes
            category = os.path.basename(root)
            
            # Éviter le dossier racine lui-même
            if category == "shellcode":
                continue
                
            # Vérifier si c'est une catégorie connue ou un dossier de shellcode
            if category in self.known_dirs:
                # C'est une catégorie, parcourir ses sous-dossiers
                for subdir in dirs:
                    shellcode_path = os.path.join(root, subdir)
                    asm_files = [f for f in os.listdir(shellcode_path) if f.endswith('.asm')]
                    
                    if asm_files:
                        # Prendre le premier fichier .asm trouvé
                        asm_file = asm_files[0]
                        raw_path = os.path.join(shellcode_path, 'raw.txt')
                        
                        if os.path.exists(raw_path):
                            shellcodes.append({
                                "name": subdir,
                                "category": category,
                                "path": os.path.join(shellcode_path, asm_file),
                                "raw_path": raw_path,
                                "description": self._extract_description(os.path.join(shellcode_path, asm_file))
                            })
            else:
                # C'est un dossier de shellcode directement
                asm_files = [f for f in files if f.endswith('.asm')]
                
                if asm_files:
                    # Prendre le premier fichier .asm trouvé
                    asm_file = asm_files[0]
                    raw_path = os.path.join(root, 'raw.txt')
                    
                    # Déterminer la catégorie basée sur le contenu du fichier asm
                    actual_category = self._determine_category(os.path.join(root, asm_file))
                    
                    if os.path.exists(raw_path):
                        shellcodes.append({
                            "name": category,
                            "category": actual_category,
                            "path": os.path.join(root, asm_file),
                            "raw_path": raw_path,
                            "description": self._extract_description(os.path.join(root, asm_file))
                        })
        
        return shellcodes
    
    def _determine_category(self, asm_file):
        """Détermine la catégorie (architecture) basée sur le contenu du fichier asm"""
        try:
            with open(asm_file, 'r') as f:
                content = f.read()
                if "bits 64" in content.lower():
                    return "Linux 64 bits"
                elif "bits 32" in content.lower():
                    return "Linux 32 bits"
                # Ajouter d'autres détections si nécessaire
        except Exception:
            pass
        
        # Par défaut
        return "Unknown"
    
    def _extract_description(self, file_path):
        """Extrait une description du fichier (première ligne de commentaire)"""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(';') or line.startswith('//') or line.startswith('#'):
                        return line[1:].strip() if line.startswith(';') else line[2:].strip()
            return "No description available"
        except Exception:
            return "No description available"
    
    def get_shellcode_content(self, raw_path):
        """Récupère le contenu du shellcode depuis un fichier précompilé"""
        try:
            with open(raw_path, 'r') as f:
                return f.read().strip()
        except Exception as e:
            raise Exception(f"Failed to read shellcode file: {str(e)}")

    


class ShellcodeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NullHunter - Shellcode Manager")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.style = DarkTheme.configure_theme(root)
        
        self.manager = ShellcodeManager()
        
        self.shellcodes = self.manager.discover_shellcodes()
        
        self._create_widgets()
        
        self._populate_shellcode_list()
    
    def _create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.selection_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.selection_tab, text="Shellcode Selection")
        
        self.results_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.results_tab, text="Shellcode Output")
        
        self._create_selection_tab()
        
        self._create_results_tab()
        
        self.statusbar = ttk.Label(self.root, text="Ready", style="Statusbar.TLabel")
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_selection_tab(self):
        top_frame = ttk.Frame(self.selection_tab)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(top_frame, text="Available Shellcodes", font=("Arial", 14))
        title_label.pack(side=tk.LEFT, pady=5)
        
        filter_frame = ttk.Frame(top_frame)
        filter_frame.pack(side=tk.RIGHT)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, 
                                    values=["All", "Linux 32 bits", "Linux 64 bits"])
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self._populate_shellcode_list())
        
        list_frame = ttk.Frame(self.selection_tab)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Name", "Category", "Description")
        self.shellcode_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.shellcode_tree.heading(col, text=col)
            self.shellcode_tree.column(col, width=100)
        
        self.shellcode_tree.column("Name", width=150)
        self.shellcode_tree.column("Category", width=100)
        self.shellcode_tree.column("Description", width=400)
        
        self.shellcode_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.shellcode_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.shellcode_tree.config(yscrollcommand=scrollbar.set)
        
        self.shellcode_tree.bind("<Double-1>", self._on_shellcode_select)
        self.shellcode_tree.bind("<Return>", self._on_shellcode_select)
        
        options_frame = ttk.Frame(self.selection_tab)
        options_frame.pack(fill=tk.X, pady=10)
        
        compile_btn = ttk.Button(options_frame, text="Load Shellcode", 
                                command=self._compile_selected_shellcode)
        compile_btn.pack(side=tk.RIGHT, padx=5)
        
        refresh_btn = ttk.Button(options_frame, text="Refresh List", 
                               command=self._refresh_shellcode_list)
        refresh_btn.pack(side=tk.RIGHT, padx=5)
    
    def _create_results_tab(self):
        info_frame = ttk.Frame(self.results_tab)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.shellcode_info = ttk.Label(info_frame, text="No shellcode loaded yet")
        self.shellcode_info.pack(side=tk.LEFT, pady=5)
        
        self.size_info = ttk.Label(info_frame, text="")
        self.size_info.pack(side=tk.RIGHT, pady=5)
        
        ttk.Separator(self.results_tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        shellcode_frame = ttk.Frame(self.results_tab)
        shellcode_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(shellcode_frame, text="Shellcode (\\x format):").pack(anchor=tk.W, pady=(0, 5))
        
        self.shellcode_text = tk.Text(shellcode_frame, wrap=tk.WORD, height=8, 
                                     bg=DARKER_BG, fg=DARK_TEXT, insertbackground=DARK_TEXT)
        self.shellcode_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(shellcode_frame, orient=tk.VERTICAL, command=self.shellcode_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.shellcode_text.config(yscrollcommand=scrollbar.set)
        
        copy_btn = ttk.Button(shellcode_frame, text="Copy Shellcode", 
                            command=lambda: self._copy_to_clipboard(self.shellcode_text))
        copy_btn.pack(anchor=tk.E, pady=5)
        
        ttk.Separator(self.results_tab, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        c_frame = ttk.Frame(self.results_tab)
        c_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(c_frame, text="C Code Snippet:").pack(anchor=tk.W, pady=(0, 5))
        
        self.c_text = tk.Text(c_frame, wrap=tk.WORD, height=8, 
                            bg=DARKER_BG, fg=DARK_TEXT, insertbackground=DARK_TEXT)
        self.c_text.pack(fill=tk.BOTH, expand=True)
        
        c_scrollbar = ttk.Scrollbar(c_frame, orient=tk.VERTICAL, command=self.c_text.yview)
        c_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.c_text.config(yscrollcommand=c_scrollbar.set)
        
        copy_c_btn = ttk.Button(c_frame, text="Copy C Snippet", 
                              command=lambda: self._copy_to_clipboard(self.c_text))
        copy_c_btn.pack(anchor=tk.E, pady=5)
    
    def _populate_shellcode_list(self):
        for item in self.shellcode_tree.get_children():
            self.shellcode_tree.delete(item)
        
        filter_value = self.filter_var.get()
        filtered_shellcodes = self.shellcodes
        if filter_value != "All":
            filtered_shellcodes = [sc for sc in self.shellcodes if sc["category"] == filter_value]
        
        for shellcode in filtered_shellcodes:
            self.shellcode_tree.insert("", tk.END, values=(
                shellcode["name"],
                shellcode["category"],
                shellcode["description"]
            ), tags=(shellcode["path"],))
        
        self.statusbar.config(text=f"Found {len(filtered_shellcodes)} shellcode(s)")
    
    def _refresh_shellcode_list(self):
        self.shellcodes = self.manager.discover_shellcodes()
        self._populate_shellcode_list()
        self.statusbar.config(text=f"Refreshed shellcode list. Found {len(self.shellcodes)} shellcode(s)")
    
    def _on_shellcode_select(self, event):
        selected_items = self.shellcode_tree.selection()
        if not selected_items:
            return
        
        item = selected_items[0]
        item_values = self.shellcode_tree.item(item, "values")
        
        selected_shellcode = None
        for sc in self.shellcodes:
            if sc["name"] == item_values[0] and sc["category"] == item_values[1]:
                selected_shellcode = sc
                break
        
        if selected_shellcode:
            self.statusbar.config(text=f"Selected: {selected_shellcode['name']}")

    def _copy_to_clipboard(self, text_widget):
        content = text_widget.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.statusbar.config(text="Copied to clipboard")

    def _compile_selected_shellcode(self):
        selected_items = self.shellcode_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "Please select a shellcode from the list")
            return
        
        item = selected_items[0]
        item_values = self.shellcode_tree.item(item, "values")
        
        selected_shellcode = None
        for sc in self.shellcodes:
            if sc["name"] == item_values[0] and sc["category"] == item_values[1]:
                selected_shellcode = sc
                break
        
        if not selected_shellcode:
            messagebox.showerror("Error", "Could not find the selected shellcode")
            return
        
        self.statusbar.config(text=f"Loading {selected_shellcode['name']}...")
        self.shellcode_info.config(text=f"Processing: {selected_shellcode['name']}")
        
        self.shellcode_text.delete(1.0, tk.END)
        self.c_text.delete(1.0, tk.END)
        
        # Utiliser un thread pour ne pas bloquer l'interface
        threading.Thread(target=self._load_shellcode_async, 
                        args=(selected_shellcode,)).start()

    def _load_shellcode_async(self, shellcode_info):
        try:
            # Charger le shellcode depuis le fichier raw.txt
            shellcode = self.manager.get_shellcode_content(shellcode_info["raw_path"])
            
            # Mettre à jour l'interface dans le thread principal
            self.root.after(0, lambda: self._update_results(shellcode, shellcode_info))
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: messagebox.showerror("Loading Error", error_msg))
            self.root.after(0, lambda: self.statusbar.config(text=f"Error: {error_msg[:50]}..."))

    def _update_results(self, shellcode, shellcode_info):
        shellcode_size = len(shellcode.replace('\\x', '')) // 2
        
        self.notebook.select(1)
        
        self.shellcode_info.config(
            text=f"Shellcode: {shellcode_info['name']} ({shellcode_info['category']})"
        )
        self.size_info.config(text=f"Size: {shellcode_size} bytes")
        
        self.shellcode_text.delete(1.0, tk.END)
        self.shellcode_text.insert(tk.END, shellcode)
        
        c_snippet = self.generate_c_snippet(shellcode, shellcode_info, shellcode_size)
        
        self.c_text.delete(1.0, tk.END)
        self.c_text.insert(tk.END, c_snippet)
        
        self.statusbar.config(
            text=f"Shellcode loaded: {shellcode_size} bytes from {shellcode_info['name']}"
        )

    def generate_c_snippet(self, shellcode, shellcode_info, shellcode_size):
        return f"""// Shellcode: {shellcode_info['name']}
// Architecture: {shellcode_info['category']}
// Size: {shellcode_size} bytes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
// Windows
#include <windows.h>
#else
// Linux/Unix
#include <sys/mman.h>
#include <unistd.h>
#endif

unsigned char shellcode[] = 
"{shellcode}";

int main() {{
    printf("Shellcode length: %lu\\n", strlen((char*)shellcode));

#ifdef _WIN32
    // Windows: Allouer de la mémoire exécutable
    void *exec = VirtualAlloc(0, sizeof(shellcode), 
                            MEM_COMMIT | MEM_RESERVE, 
                            PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {{
        printf("Erreur d'allocation mémoire\\n");
        return 1;
    }}
    memcpy(exec, shellcode, sizeof(shellcode));
        
    // Exécuter le shellcode
    ((void(*)())exec)();
        
    // Libérer la mémoire (ne sera probablement jamais atteint si shellcode = shell)
    VirtualFree(exec, 0, MEM_RELEASE);
#else
    // Linux/Unix: Allouer de la mémoire exécutable
    void *exec = mmap(0, sizeof(shellcode), 
                    PROT_READ | PROT_WRITE | PROT_EXEC, 
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec == MAP_FAILED) {{
        printf("Erreur d'allocation mémoire\\n");
        return 1;
    }}
    memcpy(exec, shellcode, sizeof(shellcode));
        
    // Vider le cache d'instructions pour certains CPUs
    // qui nécessitent cette étape après modification du code
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
    __builtin___clear_cache((char *)exec, (char *)exec + sizeof(shellcode));
#endif
        
    // Exécuter le shellcode
    ((void(*)())exec)();
        
    // Libérer la mémoire (ne sera probablement jamais atteint si shellcode = shell)
    munmap(exec, sizeof(shellcode));
#endif

    return 0;
    }}"""

def cli_mode():
    parser = argparse.ArgumentParser(description="NullHunter - Load and use shellcode from the collection")
    parser.add_argument("name", help="Name of the shellcode to load")
    parser.add_argument("-l", "--list", action="store_true", help="List available shellcodes")
    parser.add_argument("-o", "--output", help="Output file (optional)")
    parser.add_argument("-c", "--c-snippet", action="store_true", help="Generate C code snippet")
    
    args = parser.parse_args()
    
    manager = ShellcodeManager()
    
    # Lister les shellcodes disponibles
    if args.list:
        shellcodes = manager.discover_shellcodes()
        print("\nAvailable Shellcodes:")
        print("=" * 80)
        print(f"{'Name':<30} {'Category':<15} {'Description':<35}")
        print("-" * 80)
        for sc in shellcodes:
            print(f"{sc['name']:<30} {sc['category']:<15} {sc['description'][:35]:<35}")
        return 0
    
    # Charger un shellcode spécifique
    shellcodes = manager.discover_shellcodes()
    selected_shellcode = None
    
    for sc in shellcodes:
        if sc["name"].lower() == args.name.lower():
            selected_shellcode = sc
            break
    
    if not selected_shellcode:
        print(f"Error: Shellcode '{args.name}' not found in the collection.")
        print("Use --list to see available shellcodes.")
        return 1
    
    try:
        print(f"Loading {selected_shellcode['name']}...")
        shellcode = manager.get_shellcode_content(selected_shellcode["raw_path"])
        
        print("\nShellcode (\\x format):")
        print(shellcode)
        
        shellcode_size = len(shellcode.replace('\\x', '')) // 2
        
        if args.c_snippet:
            print("\nC code snippet:")
            c_snippet = f"""// Shellcode: {selected_shellcode['name']}
// Architecture: {selected_shellcode['category']}
// Size: {shellcode_size} bytes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
// Windows
#include <windows.h>
#else
// Linux/Unix
#include <sys/mman.h>
#include <unistd.h>
#endif

unsigned char shellcode[] = 
"{shellcode}";

int main() {{
    printf("Shellcode length: %lu\\n", strlen((char*)shellcode));

#ifdef _WIN32
    // Windows: Allouer de la mémoire exécutable
    void *exec = VirtualAlloc(0, sizeof(shellcode), 
                            MEM_COMMIT | MEM_RESERVE, 
                            PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {{
        printf("Erreur d'allocation mémoire\\n");
        return 1;
    }}
    memcpy(exec, shellcode, sizeof(shellcode));
    
    // Exécuter le shellcode
    ((void(*)())exec)();
    
    // Libérer la mémoire (ne sera probablement jamais atteint si shellcode = shell)
    VirtualFree(exec, 0, MEM_RELEASE);
#else
    // Linux/Unix: Allouer de la mémoire exécutable
    void *exec = mmap(0, sizeof(shellcode), 
                    PROT_READ | PROT_WRITE | PROT_EXEC, 
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec == MAP_FAILED) {{
        printf("Erreur d'allocation mémoire\\n");
        return 1;
    }}
    memcpy(exec, shellcode, sizeof(shellcode));
    
    // Vider le cache d'instructions pour certains CPUs
    // qui nécessitent cette étape après modification du code
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
    __builtin___clear_cache((char *)exec, (char *)exec + sizeof(shellcode));
#endif
    
    // Exécuter le shellcode
    ((void(*)())exec)();
    
    // Libérer la mémoire (ne sera probablement jamais atteint si shellcode = shell)
    munmap(exec, sizeof(shellcode));
#endif

    return 0;
}}"""
            print(c_snippet)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(shellcode)
            print(f"\nShellcode written to {args.output}")
        
        print(f"\nShellcode size: {shellcode_size} bytes")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


def main():
    if len(sys.argv) > 1:
        sys.exit(cli_mode())
    else:
        root = tk.Tk()
        app = ShellcodeGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()