"""Login & registration screen."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core.constants import APP_NAME, APP_VERSION
from core.exceptions import CyberSecError
from gui.components import PALETTE, font


class LoginView(ttk.Frame):
    """Centered auth card with Login / Register modes."""

    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app
        self.mode = "login"
        self._build()

    # ------------------------------------------------------------------ layout

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Decorative backdrop bars
        bg = tk.Canvas(self, background=PALETTE["bg"], highlightthickness=0)
        bg.grid(row=0, column=0, sticky="nsew")
        self._canvas = bg

        center = ttk.Frame(self, style="TFrame")
        center.place(relx=0.5, rely=0.5, anchor="center")

        wrapper = ttk.Frame(center, style="TFrame")
        wrapper.pack()

        # Brand header
        brand = ttk.Frame(wrapper, style="TFrame")
        brand.pack(pady=(0, 22))
        ttk.Label(brand, text="◤", foreground=PALETTE["accent"], background=PALETTE["bg"],
                  font=font(30, "bold")).pack(side="left", padx=(0, 12))
        titles = ttk.Frame(brand, style="TFrame")
        titles.pack(side="left")
        ttk.Label(titles, text=APP_NAME, style="H1.TLabel").pack(anchor="w")
        ttk.Label(titles, text=f"Cybersecurity Console · v{APP_VERSION}",
                  style="Muted.TLabel").pack(anchor="w")

        self.card = ttk.Frame(wrapper, style="Card.TFrame", padding=(32, 26))
        self.card.pack()

        self._build_form()
        self.bind_all("<Return>", self._on_submit)

    def _build_form(self) -> None:
        for child in self.card.winfo_children():
            child.destroy()

        title = "Sign in" if self.mode == "login" else "Create account"
        ttk.Label(self.card, text=title, style="CardH2.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        subtitle = ("Enter your credentials to access the console."
                    if self.mode == "login" else
                    "Self-registration creates a viewer account; an administrator can promote it.")
        ttk.Label(self.card, text=subtitle, style="CardMuted.TLabel", wraplength=380,
                  justify="left").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 14))

        self.username = ttk.Entry(self.card, width=34, font=font(11))
        self.password = ttk.Entry(self.card, width=34, show="●", font=font(11))
        self.confirm_pw = ttk.Entry(self.card, width=34, show="●", font=font(11))

        row = 2
        ttk.Label(self.card, text="Username", style="CardMuted.TLabel").grid(
            row=row, column=0, sticky="w"); row += 1
        self.username.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(2, 10)); row += 1
        ttk.Label(self.card, text="Password", style="CardMuted.TLabel").grid(
            row=row, column=0, sticky="w"); row += 1
        self.password.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(2, 10)); row += 1

        if self.mode == "register":
            ttk.Label(self.card, text="Confirm password", style="CardMuted.TLabel").grid(
                row=row, column=0, sticky="w"); row += 1
            self.confirm_pw.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(2, 10)); row += 1

        self.error_lbl = ttk.Label(self.card, text="", style="CardMuted.TLabel",
                                   foreground=PALETTE["danger"], wraplength=380, justify="left")
        self.error_lbl.grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 8)); row += 1

        actions = ttk.Frame(self.card, style="Card.TFrame")
        actions.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        actions.grid_columnconfigure(0, weight=1)
        submit_text = "Sign in →" if self.mode == "login" else "Create account →"
        self.submit_btn = ttk.Button(actions, text=submit_text, style="Primary.TButton",
                                     command=self._on_submit)
        self.submit_btn.grid(row=0, column=0, sticky="ew")
        self.submit_btn.bind("<Return>", lambda e: self._on_submit())

        toggle_text = ("Need an account? Register" if self.mode == "login"
                       else "← Back to sign in")
        ttk.Button(actions, text=toggle_text, style="Ghost.TButton",
                   command=self._toggle_mode).grid(row=1, column=0, sticky="ew", pady=(10, 0))

        hint = ("Demo accounts (when seeded): admin / Admin@123 · analyst / Analyst@123"
                if self.mode == "login" else "Passwords are stored only as salted PBKDF2 hashes.")
        ttk.Label(self.card, text=hint, style="CardMuted.TLabel",
                  font=font(8)).grid(row=row + 1, column=0, columnspan=2, sticky="w", pady=(14, 0))

        self.username.focus_set()

    # ------------------------------------------------------------------ actions

    def _toggle_mode(self) -> None:
        self.mode = "register" if self.mode == "login" else "login"
        self.error_lbl.configure(text="")
        self._build_form()

    def _fail(self, message: str) -> None:
        self.error_lbl.configure(text=message)
        self.app.status(message, "error")

    def _on_submit(self, event=None) -> None:
        if self.mode == "login":
            self._do_login()
        else:
            self._do_register()

    def _do_login(self) -> None:
        username = self.username.get().strip()
        password = self.password.get()
        if not username or not password:
            self._fail("Please enter both username and password.")
            return
        self.submit_btn.state(["disabled"])
        try:
            self.app.services.auth.login(username, password)
        except CyberSecError as exc:
            self.submit_btn.state(["!disabled"])
            self._fail(exc.user_message)
            return
        except Exception as exc:  # noqa: BLE001
            self.submit_btn.state(["!disabled"])
            self._fail(f"Unexpected error: {exc}")
            return
        self.submit_btn.state(["!disabled"])
        self.app.on_login_success()

    def _do_register(self) -> None:
        username = self.username.get().strip()
        password = self.password.get()
        confirm = self.confirm_pw.get()
        if not username or not password:
            self._fail("Please enter both username and password.")
            return
        if password != confirm:
            self._fail("Passwords do not match.")
            return
        self.submit_btn.state(["disabled"])
        try:
            self.app.services.auth.register(username, password)
        except CyberSecError as exc:
            self.submit_btn.state(["!disabled"])
            self._fail(exc.user_message)
            return
        except Exception as exc:  # noqa: BLE001
            self.submit_btn.state(["!disabled"])
            self._fail(f"Unexpected error: {exc}")
            return
        self.submit_btn.state(["!disabled"])
        try:
            self.app.services.auth.login(username, password)
        except CyberSecError:
            self.mode = "login"
            self._build_form()
            self.error_lbl.configure(text="Account created — please sign in.")
            return
        self.app.on_login_success()
