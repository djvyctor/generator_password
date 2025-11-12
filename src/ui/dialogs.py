from __future__ import annotations
import customtkinter as ctk
from tkinter import messagebox

class AddDialog(ctk.CTkToplevel):
    """Diálogo para adicionar uma nova entrada de senha."""
    def __init__(self, parent, on_save):
        super().__init__(parent)
        self.title("Adicionar senha")
        self.resizable(False, False)
        self.on_save = on_save
        self.grab_set()
        ctk.CTkLabel(self, text="Serviço").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.service_entry = ctk.CTkEntry(self, width=280)
        self.service_entry.grid(row=1, column=0, padx=10, sticky="ew")
        ctk.CTkLabel(self, text="Usuário").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 4))
        self.username_entry = ctk.CTkEntry(self, width=280)
        self.username_entry.grid(row=3, column=0, padx=10, sticky="ew")
        ctk.CTkLabel(self, text="Senha").grid(row=4, column=0, sticky="w", padx=10, pady=(10, 4))
        self.password_entry = ctk.CTkEntry(self, width=280)
        self.password_entry.grid(row=5, column=0, padx=10, sticky="ew")
        btns = ctk.CTkFrame(self)
        btns.grid(row=6, column=0, sticky="ew", padx=10, pady=10)
        save_btn = ctk.CTkButton(btns, text="Salvar", command=self._save)
        save_btn.pack(side="left")
        cancel_btn = ctk.CTkButton(btns, text="Cancelar", command=self.destroy)
        cancel_btn.pack(side="left", padx=8)

    def _save(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not service or not password:
            messagebox.showwarning("Aviso", "Informe ao menos serviço e senha.")
            return
        self.on_save(service, username, password)
        self.destroy()
