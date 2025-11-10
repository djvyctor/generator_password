from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, Optional

import customtkinter as ctk
import pyperclip

from src.auth.master_key import (
	MASTER_KEY_PATH,
	verify_master_key,
	create_master_key,
	derive_key,
)
from src.features import manager


class LoginFrame(ctk.CTkFrame):
	"""Frame de autenticação/criação de senha master."""

	def __init__(self, master: "PasswordManagerApp"):
		super().__init__(master)
		self.app = master

		self.columnconfigure(0, weight=1)

		self.title = ctk.CTkLabel(self, text="Password Manager", font=ctk.CTkFont(size=18, weight="bold"))
		self.title.grid(row=0, column=0, pady=(20, 10), padx=20)

		self.info = ctk.CTkLabel(self, text="Digite sua senha master" if os.path.exists(MASTER_KEY_PATH)
								  else "Crie sua senha master")
		self.info.grid(row=1, column=0, pady=(0, 10), padx=20)

		self.pw_entry = ctk.CTkEntry(self, placeholder_text="Senha master", show="*")
		self.pw_entry.grid(row=2, column=0, sticky="ew", padx=20)

		self.confirm_entry: Optional[ctk.CTkEntry] = None
		if not os.path.exists(MASTER_KEY_PATH):
			self.confirm_entry = ctk.CTkEntry(self, placeholder_text="Confirmar senha", show="*")
			self.confirm_entry.grid(row=3, column=0, sticky="ew", padx=20, pady=(8, 0))

		self.btn = ctk.CTkButton(self, text="Entrar" if os.path.exists(MASTER_KEY_PATH) else "Criar",
								  command=self._on_submit)
		self.btn.grid(row=4, column=0, pady=16)

	def _on_submit(self):
		pwd = self.pw_entry.get().strip()
		if not pwd:
			messagebox.showwarning("Aviso", "Informe a senha master.")
			return

		if os.path.exists(MASTER_KEY_PATH):
			if not verify_master_key(pwd):
				messagebox.showerror("Erro", "Senha master incorreta.")
				return

			with open(MASTER_KEY_PATH, "rb") as f:
				data = f.read()
			salt = data[:16]
			key = derive_key(pwd, salt)
			self.app.on_authenticated(key)
		else:
			# Criar senha master
			if not self.confirm_entry:
				messagebox.showerror("Erro", "Confirmação de senha indisponível.")
				return
			confirm = self.confirm_entry.get().strip()
			if confirm != pwd:
				messagebox.showerror("Erro", "As senhas não coincidem.")
				return
			create_master_key(pwd)
			messagebox.showinfo("Pronto", "Senha master criada com sucesso.")
			with open(MASTER_KEY_PATH, "rb") as f:
				data = f.read()
			salt = data[:16]
			key = derive_key(pwd, salt)
			self.app.on_authenticated(key)


class VaultFrame(ctk.CTkFrame):
	"""Frame principal: lista senhas e ações básicas."""

	def __init__(self, master: "PasswordManagerApp", key: bytes):
		super().__init__(master)
		self.app = master
		self.key = key

		self.columnconfigure(0, weight=1)
		self.rowconfigure(1, weight=1)

		top_bar = ctk.CTkFrame(self)
		top_bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 0))
		add_btn = ctk.CTkButton(top_bar, text="Adicionar", command=self._add)
		add_btn.pack(side=tk.LEFT, padx=(8, 4), pady=6)
		rem_btn = ctk.CTkButton(top_bar, text="Remover", command=self._remove)
		rem_btn.pack(side=tk.LEFT, padx=4, pady=6)
		copy_btn = ctk.CTkButton(top_bar, text="Copiar senha", command=self._copy)
		copy_btn.pack(side=tk.LEFT, padx=4, pady=6)

		self.tree = ttk.Treeview(self, columns=("service", "username"), show="headings", height=12)
		self.tree.heading("service", text="Serviço")
		self.tree.heading("username", text="Usuário")
		self.tree.column("service", width=180)
		self.tree.column("username", width=200)
		self.tree.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

		vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
		self.tree.configure(yscrollcommand=vsb.set)
		vsb.grid(row=1, column=1, sticky="ns", pady=8)

		self._reload()

	def _reload(self):
		for i in self.tree.get_children():
			self.tree.delete(i)
		try:
			data = manager.load_vault(self.key)
		except Exception as e:
			messagebox.showerror("Erro", f"Não foi possível carregar o cofre: {e}")
			data = {}
		for service, obj in sorted(data.items()):
			username = obj.get("username", "") if isinstance(obj, dict) else ""
			self.tree.insert("", tk.END, values=(service, username))

	def _selected_service(self) -> Optional[str]:
		sel = self.tree.selection()
		if not sel:
			return None
		values = self.tree.item(sel[0], "values")
		return values[0] if values else None

	def _add(self):
		AddDialog(self, on_save=self._on_add_saved)

	def _on_add_saved(self, service: str, username: str, password: str):
		try:
			manager.add_password(service, username, password, self.key)
			self._reload()
		except Exception as e:
			messagebox.showerror("Erro", f"Falha ao adicionar: {e}")

	def _remove(self):
		service = self._selected_service()
		if not service:
			messagebox.showinfo("Info", "Selecione um item para remover.")
			return
		if messagebox.askyesno("Confirmação", f"Remover '{service}'?"):
			try:
				manager.remove_password(service, self.key)
				self._reload()
			except Exception as e:
				messagebox.showerror("Erro", f"Falha ao remover: {e}")

	def _copy(self):
		service = self._selected_service()
		if not service:
			messagebox.showinfo("Info", "Selecione um item para copiar a senha.")
			return
		try:
			entry = manager.get_password(service, self.key)
			if not entry:
				messagebox.showwarning("Aviso", "Entrada não encontrada.")
				return
			pyperclip.copy(entry.get("password", ""))
			messagebox.showinfo("Copiado", "Senha copiada para a área de transferência.")
		except Exception as e:
			messagebox.showerror("Erro", f"Falha ao copiar: {e}")


class AddDialog(ctk.CTkToplevel):
	def __init__(self, parent: VaultFrame, on_save):
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
		save_btn.pack(side=tk.LEFT)
		cancel_btn = ctk.CTkButton(btns, text="Cancelar", command=self.destroy)
		cancel_btn.pack(side=tk.LEFT, padx=8)

	def _save(self):
		service = self.service_entry.get().strip()
		username = self.username_entry.get().strip()
		password = self.password_entry.get().strip()
		if not service or not password:
			messagebox.showwarning("Aviso", "Informe ao menos serviço e senha.")
			return
		self.on_save(service, username, password)
		self.destroy()


class PasswordManagerApp(ctk.CTk):
	def __init__(self):
		super().__init__()
		self.title("Password Manager")
		self.geometry("600x420")
		ctk.set_appearance_mode("system")
		ctk.set_default_color_theme("blue")

		self.current_frame: Optional[ctk.CTkFrame] = None
		self._show_login()

	def _show_login(self):
		self._swap(LoginFrame(self))

	def on_authenticated(self, key: bytes):
		self._swap(VaultFrame(self, key))

	def _swap(self, frame: ctk.CTkFrame):
		if self.current_frame is not None:
			self.current_frame.destroy()
		self.current_frame = frame
		self.current_frame.pack(fill="both", expand=True)


def main():
	app = PasswordManagerApp()
	app.mainloop()


if __name__ == "__main__":
	main()

