import tkinter as tk
from tkinter import filedialog, messagebox
import os
import Encript_Code as ec
import binascii

# Define color constants
BG_COLOR = "#000000"      # Black
FG_COLOR = "#39FF14"      # Electric green
ENTRY_BG = "#101010"      # Slightly lighter black for entries
BUTTON_BG = "#101010"
LISTBOX_BG = "#101010"
TEXT_BG = "#101010"

class FolderEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Folder Encryption GUI")
        self.root.geometry("900x500")
        self.root.configure(bg=BG_COLOR)

        # ===== Top Frame: Key Input =====
        top_frame = tk.Frame(root, height=50, pady=10, bg=BG_COLOR)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(top_frame, text="Enter Encryption Key:", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.key_entry = tk.Entry(top_frame, show="*", bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tk.Button(top_frame, text="Use Text File", bg=BUTTON_BG, fg=FG_COLOR, command=self.load_key_from_file).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Create New Key", bg=BUTTON_BG, fg=FG_COLOR, command=self.create_new_key).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Save Key", bg=BUTTON_BG, fg=FG_COLOR, command=self.save_key).pack(side=tk.LEFT, padx=5)

        # ===== Middle Frame: Folder Selection =====
        middle_frame = tk.Frame(root, height=50, bg=BG_COLOR)
        middle_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(middle_frame, text="Select Folder:", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.folder_path_var = tk.StringVar()
        self.folder_entry = tk.Entry(middle_frame, textvariable=self.folder_path_var, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(middle_frame, text="Browse", bg=BUTTON_BG, fg=FG_COLOR, command=self.browse_folder).pack(side=tk.LEFT, padx=5)

        # ===== Bottom Frame =====
        bottom_frame = tk.Frame(root, bg=BG_COLOR)
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ===== Left panel: Folder contents =====
        self.folder_panel = tk.Frame(bottom_frame, width=250, bg=BG_COLOR)
        self.folder_panel.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(self.folder_panel, text="Folder Contents", bg=BG_COLOR, fg=FG_COLOR).pack(pady=5)
        self.file_listbox = tk.Listbox(self.folder_panel, bg=LISTBOX_BG, fg=FG_COLOR, selectbackground=FG_COLOR, selectforeground=BG_COLOR)
        self.file_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.file_listbox.bind("<<ListboxSelect>>", self.display_selected_file)

        # ===== Right panel: Visualization =====
        self.visual_panel = tk.Frame(bottom_frame, bg=BG_COLOR)
        self.visual_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(self.visual_panel, text="Visualization Panel", bg=BG_COLOR, fg=FG_COLOR).pack(pady=5)
        self.preview_text = tk.Text(self.visual_panel, wrap=tk.WORD, state=tk.DISABLED, bg=TEXT_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ===== Button Bar =====
        button_frame = tk.Frame(self.visual_panel, bg=BG_COLOR)
        button_frame.pack(fill=tk.X, pady=5)

        tk.Button(button_frame, text="Encrypt File", bg=BUTTON_BG, fg=FG_COLOR, command=self.encrypt_selected_file).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Decrypt File", bg=BUTTON_BG, fg=FG_COLOR, command=self.decrypt_selected_file).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Delete File", bg=BUTTON_BG, fg=FG_COLOR, command=self.delete_selected_file).pack(side=tk.LEFT, padx=10)

        self.filename = None
        self.key = None
        self.folder = None

    # -------------------------------------------------
    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path_var.set(folder_selected)
            self.populate_folder_contents(folder_selected)

    def populate_folder_contents(self, folder_path):
        self.file_listbox.delete(0, tk.END)
        for entry in os.listdir(folder_path):
            full_path = os.path.join(folder_path, entry)
            if os.path.isfile(full_path):
                self.file_listbox.insert(tk.END, entry)

    def display_selected_file(self, event):
        if not self.file_listbox.curselection():
            return

        index = self.file_listbox.curselection()[0]
        filename = self.file_listbox.get(index)
        folder = self.folder_path_var.get()
        full_path = os.path.join(folder, filename)

        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.filename = filename
        self.folder = folder
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read(5000)
            self.preview_text.insert(tk.END, content)
        except Exception:
            size = os.path.getsize(full_path)
            ext = os.path.splitext(filename)[1]
            info = (
                f"Binary or non-text file\n\n"
                f"Filename: {filename}\n"
                f"Extension: {ext}\n"
                f"Size: {size} bytes\n"
            )
            self.preview_text.insert(tk.END, info)
        self.preview_text.config(state=tk.DISABLED)

    # -------------------------------------------------
    def encrypt_selected_file(self):
        if not self.file_listbox.curselection():
            messagebox.showwarning("No file selected", "Please select a file to encrypt.")
            return
        if self.filename is not None and self.key is not None:
            print(self.filename)
            print(self.key.encode("utf-8"))
            blob = ec.encrypt_file(self.filename, self.key.encode("utf-8"))
            ec.save_encrypted_file(self.filename, blob)
        self.populate_folder_contents(self.folder)

    def decrypt_selected_file(self):
        if not self.file_listbox.curselection():
            messagebox.showwarning("No file selected", "Please select a file to decrypt.")
            return

        try:
            with open(self.filename, "rb") as f:
                encrypted_data = f.read()

            # Attempt decryption (replace with your actual decrypt function)
            restored_file = ec.decrypt_file(encrypted_data, self.key.encode("utf-8"))
            print("Decrypted as:", restored_file)
            self.populate_folder_contents(self.folder)

        except Exception as e:
            # Catch any exception related to decryption failure (wrong key)
            messagebox.showerror("Decryption Failed", "The key is incorrect or the file is corrupted!")
            print("Decryption error:", str(e))

    def delete_selected_file(self):
        if not self.file_listbox.curselection():
            messagebox.showwarning("No file selected", "Please select a file to delete.")
            return
        index = self.file_listbox.curselection()[0]
        filename = self.file_listbox.get(index)
        folder = self.folder_path_var.get()
        full_path = os.path.join(folder, filename)
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{filename}'?"):
            return
        try:
            os.remove(full_path)
            self.file_listbox.delete(index)
            messagebox.showinfo("Deleted", f"'{filename}' has been deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file:\n{e}")
        self.populate_folder_contents(self.folder)

    def load_key_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Text File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    key_content = f.read().strip()
                    self.key = key_content
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(0, key_content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")

    def create_new_key(self):
        key_bytes = os.urandom(32)
        key_hex = binascii.hexlify(key_bytes).decode()
        self.key = key_hex
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key_hex)
        messagebox.showinfo("New Key Generated",
                            "A new 256-bit key has been generated and placed in the entry field.")

    def save_key(self):
        with open("key.txt", "wb") as f:
            f.write(self.key.encode("utf-8"))
        print("Key Save Successfully")


# =====================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = FolderEncryptorApp(root)
    root.mainloop()
