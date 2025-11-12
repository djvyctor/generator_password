from __future__ import annotations
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk

PRIMARY_COLOR = "#6B7280"  # cinza médio
ACCENT_COLOR = "#9CA3AF"   # cinza claro
BG_DARK = "#0F172A"        # slate-900 (muito escuro)
BG_MEDIUM = "#1E293B"      # slate-800 (médio escuro)
BG_LIGHT = "#334155"       # slate-700 (cards/frames)
TEXT = "#E5E7EB"           # gray-200 (texto principal)
TEXT_SECONDARY = "#9CA3AF" # gray-400 (texto secundário)
FONT_FAMILY = "Segoe UI"
FONT_SIZE = 12
TITLE_SIZE = 18


def style_ttk(root: tk.Misc) -> None:
    style = ttk.Style(master=root)
    try:
        style.theme_use("default")
    except tk.TclError:
        pass
    style.configure(
        "Treeview",
        background=BG_MEDIUM,
        fieldbackground=BG_MEDIUM,
        foreground=TEXT,
        rowheight=28,
        borderwidth=0,
        font=(FONT_FAMILY, FONT_SIZE),
    )
    style.configure("Treeview.Heading", 
                   background=BG_DARK,
                   foreground=TEXT,
                   font=(FONT_FAMILY, FONT_SIZE, "bold"))
    style.map("Treeview", 
             background=[("selected", BG_LIGHT)],
             foreground=[("selected", TEXT)])


def apply_theme(app: ctk.CTk) -> None:
    """Aplica aparência dark moderna totalmente cinza."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app.configure(fg_color=BG_DARK)
    ctk.ThemeManager.theme["CTkButton"]["fg_color"] = [BG_LIGHT, BG_LIGHT]
    ctk.ThemeManager.theme["CTkButton"]["hover_color"] = [ACCENT_COLOR, ACCENT_COLOR]
    ctk.ThemeManager.theme["CTkButton"]["text_color"] = [TEXT, TEXT]
    ctk.ThemeManager.theme["CTkEntry"]["fg_color"] = [BG_MEDIUM, BG_MEDIUM]
    ctk.ThemeManager.theme["CTkEntry"]["border_color"] = [PRIMARY_COLOR, PRIMARY_COLOR]
    ctk.ThemeManager.theme["CTkFrame"]["fg_color"] = [BG_MEDIUM, BG_MEDIUM]
    ctk.ThemeManager.theme["CTkFrame"]["border_color"] = [PRIMARY_COLOR, PRIMARY_COLOR]
    style_ttk(app)
