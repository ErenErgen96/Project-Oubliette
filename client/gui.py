import os
import sys
import threading
import subprocess
import customtkinter as ctk
from tkinter import filedialog, messagebox
import main_vault
from storage_manager import VaultStorage

# Configuration Import
try:
    import config
except ImportError:
    # Fallback if config missing
    class Config:
        APP_NAME = "Oubliette Endpoint Protection"
        VERSION = "3.2.0"
    config = Config()

# --- THEME SETTINGS ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class OublietteApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME} v{config.VERSION} | Command Center")
        self.geometry("700x600")
        self.resizable(False, False)
        
        # State Variables
        self.current_container = ""
        self.current_mount = ""
        self.new_duress_tokens = None # Refactored from 'panic_pwd_input'
        self.fuse_thread = None
        self.fuse_running = False 

        self.show_login_screen()

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    # ==========================================
    # 1. AUTHENTICATION & SETUP SCREEN
    # ==========================================
    def show_login_screen(self):
        self.clear_screen()
        
        # Professional Header
        ctk.CTkLabel(self, text="PROJECT OUBLIETTE", font=("Courier New", 30, "bold"), text_color="#00ff00").pack(pady=(30, 5))
        ctk.CTkLabel(self, text="Zero-Trust Data Leak Prevention Endpoint", text_color="gray").pack(pady=(0, 20))

        # 1. Container Selection
        ctk.CTkLabel(self, text="1. SECURE CONTAINER PATH", anchor="w", font=("Arial", 11, "bold")).pack(padx=40, fill="x")
        frame_file = ctk.CTkFrame(self)
        frame_file.pack(pady=(5, 15), padx=40, fill="x")
        
        self.entry_file = ctk.CTkEntry(frame_file, placeholder_text="Select encrypted vault container...")
        self.entry_file.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        
        ctk.CTkButton(frame_file, text="📂", width=40, command=self.select_file).pack(side="right", padx=(0, 5))
        ctk.CTkButton(frame_file, text="➕ NEW", width=60, fg_color="#444", command=self.open_setup_dialog).pack(side="right", padx=(0, 5))

        # 2. Mount Point
        ctk.CTkLabel(self, text="2. MOUNT POINT (Drive Letter)", anchor="w", font=("Arial", 11, "bold")).pack(padx=40, fill="x")
        self.entry_mount = ctk.CTkEntry(self, placeholder_text="Z:")
        self.entry_mount.pack(pady=(5, 15), padx=40, fill="x")
        self.entry_mount.insert(0, "Z:")

        # 3. Credentials
        ctk.CTkLabel(self, text="3. MASTER ACCESS KEY", anchor="w", font=("Arial", 11, "bold")).pack(padx=40, fill="x")
        self.entry_pass = ctk.CTkEntry(self, show="*", placeholder_text="Enter Decryption Password")
        self.entry_pass.pack(pady=(5, 20), padx=40, fill="x")

        # Initiate Button
        self.btn_login = ctk.CTkButton(self, text="AUTHENTICATE & MOUNT", height=50, font=("Arial", 14, "bold"), 
                                       fg_color="#00aa00", hover_color="#007700", command=self.start_mount_process)
        self.btn_login.pack(pady=20, padx=60, fill="x")
        
        self.lbl_status = ctk.CTkLabel(self, text="System Ready. Waiting for input...", text_color="gray")
        self.lbl_status.pack(side="bottom", pady=20)

    # ==========================================
    # 2. SECURE SESSION DASHBOARD
    # ==========================================
    def show_dashboard_screen(self):
        self.clear_screen()
        main_frame = ctk.CTkFrame(self, border_width=2, border_color="#00ff00")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(main_frame, text="SECURE CHANNEL ESTABLISHED", font=("Courier New", 24, "bold"), text_color="#00ff00").pack(pady=(40, 20))
        
        info = f"Container: {os.path.basename(self.current_container)}\nMount Point: {self.current_mount}\nProtocol: AES-256-XTS"
        ctk.CTkLabel(main_frame, text=info, font=("Consolas", 14), text_color="white").pack(pady=10)

        ctk.CTkButton(main_frame, text="OPEN SECURE DRIVE", height=40, command=self.open_explorer).pack(pady=10, padx=60, fill="x")
        
        ctk.CTkButton(main_frame, text="TERMINATE SESSION", height=40, fg_color="#aa0000", command=self.unmount_and_exit).pack(pady=10, padx=60, fill="x")

        # Enterprise Terminology
        btn_sanitize = ctk.CTkButton(main_frame, text="⚠️ EMERGENCY KEY REVOCATION", height=40, font=("Arial", 12, "bold"),
                                     fg_color="black", text_color="red", border_width=1, border_color="red",
                                     hover_color="#220000", command=self.sanitize_sequence)
        btn_sanitize.pack(side="bottom", pady=30, padx=60, fill="x")

    # ==========================================
    # BUSINESS LOGIC
    # ==========================================
    def select_file(self):
        f = filedialog.askopenfilename(filetypes=[("Secure Container", "*.dat *.bin")])
        if f: self.entry_file.delete(0, "end"); self.entry_file.insert(0, f)
        self.new_duress_tokens = None

    def open_setup_dialog(self):
        """Dialog to configure new container security policies."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Configure Security Protocols")
        dialog.geometry("500x380")
        dialog.attributes("-topmost", True)

        ctk.CTkLabel(dialog, text="Define Duress / Revocation Tokens", font=("Arial", 14, "bold")).pack(pady=(20, 10))
        
        info_text = (
            "Enter tokens that will trigger IMMEDIATE KEY REVOCATION.\n"
            "Separate multiple tokens with commas.\n"
            "If these are used during login, data becomes permanently inaccessible."
        )
        ctk.CTkLabel(dialog, text=info_text, text_color="gray", font=("Arial", 11)).pack(pady=5)

        entry_duress = ctk.CTkEntry(dialog, placeholder_text="e.g. REVOKE_CODE_1, SILENT_ALARM_99")
        entry_duress.pack(pady=10, padx=20, fill="x")

        def confirm_creation():
            raw_input = entry_duress.get()
            if not raw_input:
                messagebox.showerror("Policy Error", "At least one Duress Token is required.", parent=dialog)
                return
            
            # Parse tokens
            tokens_list = [t.strip() for t in raw_input.split(",") if t.strip()]
            
            if not tokens_list:
                messagebox.showerror("Format Error", "Invalid token format.", parent=dialog)
                return

            f = filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("Secure Container", "*.dat *.bin")], parent=dialog)
            if f:
                self.entry_file.delete(0, "end")
                self.entry_file.insert(0, f)
                self.new_duress_tokens = tokens_list # Store for initialization
                
                msg = f"Container initialized.\nActive Revocation Tokens: {len(tokens_list)}\n\nPlease enter the MASTER PASSWORD on the main screen."
                messagebox.showinfo("Configuration Saved", msg, parent=dialog)
                dialog.destroy()

        ctk.CTkButton(dialog, text="INITIALIZE CONTAINER", fg_color="#00aa00", command=confirm_creation).pack(pady=20)

    def start_mount_process(self):
        self.current_container = self.entry_file.get()
        self.current_mount = self.entry_mount.get()
        password = self.entry_pass.get()

        if not self.current_container or not self.current_mount or not password:
            messagebox.showerror("Input Error", "All fields are required.")
            return

        self.lbl_status.configure(text="Establishing Secure Link with KMS...", text_color="#00ff00")
        self.btn_login.configure(state="disabled")

        self.fuse_thread = threading.Thread(target=self.run_fuse_backend, args=(password,))
        self.fuse_thread.daemon = True
        self.fuse_thread.start()

    def run_fuse_backend(self, password):
        try:
            # CRITICAL: We pass 'duress_tokens' to match the updated storage_manager.py
            # If it's an existing vault, new_duress_tokens is None (which is correct).
            test_vault = VaultStorage(self.current_container, password, duress_tokens=self.new_duress_tokens)
            
            # Clear memory
            self.new_duress_tokens = None 
            
            self.after(100, self.show_dashboard_screen)
            
            self.fuse_running = True
            main_vault.start_fuse(self.current_container, self.current_mount, password)
            
        except Exception as e:
            msg = str(e)
            print(f"DEBUG ERROR: {msg}") 
            self.fuse_running = False
            self.after(100, lambda: self.handle_error(msg))

    def handle_error(self, msg):
        self.lbl_status.configure(text=f"Error: {msg}", text_color="red")
        self.btn_login.configure(state="normal")
        messagebox.showerror("Access Denied / System Error", msg)

    def open_explorer(self):
        try: os.startfile(self.current_mount)
        except: pass

    def unmount_and_exit(self):
        if self.fuse_running and self.current_mount:
            try:
                drive_letter = self.current_mount.rstrip(":/\\").upper()
                if len(drive_letter) == 1:
                    print(f"[*] Terminating session on {drive_letter}: via NET USE...")
                    subprocess.run(
                        ["net", "use", f"{drive_letter}:", "/delete", "/y"], 
                        shell=True, 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
            except Exception as e:
                print(f"[!] Termination warning: {e}")

        self.destroy()
        sys.exit(0)

    def sanitize_sequence(self):
        msg = messagebox.askyesno("EMERGENCY REVOCATION", "⚠ CONFIRM KEY REVOCATION? ⚠\n\nThis will immediately sever the connection and wipe cryptographic keys from RAM.")
        if msg:
            if self.fuse_running and self.current_mount:
                try:
                    drive_letter = self.current_mount.rstrip(":/\\").upper()
                    if len(drive_letter) == 1:
                        subprocess.run(["net", "use", f"{drive_letter}:", "/delete", "/y"], 
                                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except: pass
            
            self.destroy()
            sys.exit(0)

if __name__ == "__main__":
    app = OublietteApp()
    app.mainloop()