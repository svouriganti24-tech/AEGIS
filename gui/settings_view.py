"""Settings & administration: app config, security policy, users, account."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from core.exceptions import CyberSecError
from core.constants import Roles
from core.utils import humanize_timestamp
from gui.components import PALETTE, BaseView, card, font

# editable config fields: (attribute, label, kind)
APP_FIELDS = [
    ("default_scan_timeout", "Default scan timeout (s)", "float"),
    ("max_scan_threads", "Max scanner threads", "int"),
    ("max_ports_per_scan", "Max ports per scan", "int"),
    ("max_concurrent_scans", "Max concurrent scans", "int"),
]
SECURITY_FIELDS = [
    ("session_timeout_minutes", "Session timeout (minutes)", "int"),
    ("max_login_attempts", "Max login attempts before lockout", "int"),
    ("lockout_minutes", "Account lockout duration (minutes)", "int"),
    ("min_password_length", "Minimum account password length", "int"),
    ("brute_force_threshold", "Brute-force rule threshold (failures)", "int"),
    ("brute_force_window_seconds", "Brute-force window (seconds)", "int"),
    ("event_rate_threshold", "Event-rate rule threshold (events/min)", "int"),
    ("alert_escalation_threshold", "Alert escalation threshold (occurrences)", "int"),
]


class SettingsView(BaseView):
    view_title = "Settings & Administration"

    def build(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky="nsew")
        notebook.enable_traversal()

        self.tab_app = ttk.Frame(notebook, style="TFrame")
        self.tab_security = ttk.Frame(notebook, style="TFrame")
        self.tab_users = ttk.Frame(notebook, style="TFrame")
        self.tab_account = ttk.Frame(notebook, style="TFrame")
        notebook.add(self.tab_app, text="  Application  ")
        notebook.add(self.tab_security, text="  Security & Detection  ")
        if self.app.services.auth.has_permission("users.view"):
            notebook.add(self.tab_users, text="  User Management  ")
        notebook.add(self.tab_account, text="  My Account  ")

        self._build_config_tab(self.tab_app, APP_FIELDS, "Scanning")
        self._build_config_tab(self.tab_security, SECURITY_FIELDS, "Security policy & detection thresholds")
        if self.app.services.auth.has_permission("users.view"):
            self._build_users_tab()
        self._build_account_tab()

    # -------------------------------------------------------------- config tabs

    def _build_config_tab(self, tab, fields, group_title: str) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        holder = ttk.Frame(tab, style="TFrame")
        holder.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        holder.grid_columnconfigure(0, weight=1)

        form_card = card(holder)
        form_card.grid(row=0, column=0, sticky="nsew")
        form_card.grid_columnconfigure(1, weight=1)

        ttk.Label(form_card, text=group_title.upper(), style="CardMuted.TLabel",
                  font=font(9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self._field_vars: dict[str, tk.StringVar] = getattr(self, "_field_vars", {})
        row = 1
        for attr, label, kind in fields:
            var = tk.StringVar(value=str(getattr_nested(self.services.config, attr)))
            self._field_vars[attr] = var
            ttk.Label(form_card, text=label, style="Card.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 16), pady=3)
            entry = ttk.Entry(form_card, textvariable=var, width=16)
            entry.grid(row=row, column=1, sticky="w", pady=3)
            if not self.app.services.auth.has_permission("settings.manage"):
                entry.state(["disabled"])
            row += 1

        actions = ttk.Frame(form_card, style="Card.TFrame")
        actions.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        can_manage = self.app.services.auth.has_permission("settings.manage")
        ttk.Button(actions, text="Save settings", style="Primary.TButton",
                   command=lambda: self._save_settings(fields), state="!disabled" if can_manage else "disabled").pack(side="left")
        hint = ("" if can_manage
                else "Only administrators can modify these values.")
        ttk.Label(actions, text=hint, style="CardMuted.TLabel").pack(side="left", padx=(12, 0))

        if hasattr(self.services.config, "detection"):
            det_note = ("Rule thresholds are validated when saved; brute-force and event-rate "
                        "rules are evaluated against the live event stream in real time.")
            ttk.Label(form_card, text=det_note, style="CardMuted.TLabel",
                      wraplength=520, justify="left").grid(row=row + 1, column=0,
                                                           columnspan=2, sticky="w", pady=(10, 0))

    def _save_settings(self, fields) -> None:
        cfg = self.services.config
        detection_cfg = getattr(cfg, "detection", None)
        updates: dict[str, object] = {}
        for attr, _label, kind in fields:
            raw = self._field_vars[attr].get().strip()
            try:
                if attr.startswith(("brute_force", "event_rate")) and detection_cfg is not None:
                    value = self._parse(raw, kind)
                    setattr(detection_cfg, attr, value)
                    updates[attr] = value
                    continue
                value = self._parse(raw, kind)
                updates[attr] = value
            except (TypeError, ValueError):
                self.show_error("Settings", f"'{attr}' must be a number.")
                return

        # validate the whole config before applying
        from core.exceptions import ConfigurationError
        backup = {k: getattr(cfg, k) for k in updates if hasattr(cfg, k)}
        for key, value in updates.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        try:
            cfg.validate()
        except ConfigurationError as exc:
            for key, value in backup.items():
                setattr(cfg, key, value)
            self.show_error("Settings", str(exc))
            return

        if detection_cfg is not None:
            for key, value in updates.items():
                if key.startswith(("brute_force", "event_rate")):
                    setattr(detection_cfg, key, value)
        cfg.save()
        self.services.settings.set("last_settings_save", "true",
                                   updated_by=self.current_user.username)
        self.app.services.event_processor.submit(
            "SETTINGS_CHANGED", "settings",
            f"Configuration updated by {self.current_user.username} ({', '.join(updates)})",
            severity=__import__("core.constants", fromlist=["Severity"]).Severity.LOW,
            username=self.current_user.username,
        )
        self.notify(f"Saved {len(updates)} setting(s).", "success")

    @staticmethod
    def _parse(raw: str, kind: str):
        if kind == "int":
            return int(float(raw))
        if kind == "float":
            return float(raw)
        return raw

    # ---------------------------------------------------------------- users tab

    def _build_users_tab(self) -> None:
        tab = self.tab_users
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        toolbar = card(tab, padding=(12, 10))
        toolbar.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        can_manage = self.app.services.auth.has_permission("users.manage")
        ttk.Button(toolbar, text="Reset password…", style="TButton",
                   command=self._reset_password, state="!disabled" if can_manage else "disabled").pack(side="left")
        ttk.Button(toolbar, text="Toggle active", style="TButton",
                   command=self._toggle_active, state="!disabled" if can_manage else "disabled").pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Change role →", style="TButton",
                   command=self._change_role, state="!disabled" if can_manage else "disabled").pack(side="left", padx=(8, 0))
        role_combo = ttk.Combobox(toolbar, state="readonly", width=10,
                                  values=[r.value for r in Roles])
        role_combo.current(2)
        role_combo.pack(side="left", padx=(8, 0))
        self.role_choice = role_combo

        list_card = ttk.Frame(tab, style="Card.TFrame", padding=(12, 10))
        list_card.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        list_card.grid_rowconfigure(1, weight=1)
        list_card.grid_columnconfigure(0, weight=1)

        self.users_summary = ttk.Label(list_card, text="", style="CardMuted.TLabel")
        self.users_summary.grid(row=0, column=0, sticky="w", pady=(0, 6))

        from gui.components import make_treeview, striped_rows
        frame, self.users_tree = make_treeview(
            list_card,
            [("id", "#", 46, "w"), ("username", "Username", 160, "w"),
             ("role", "Role", 90, "w"), ("active", "Active", 70, "center"),
             ("created", "Created", 140, "w"), ("last_login", "Last login", 140, "w"),
             ("failed", "Failed logins", 100, "center")],
            height=10,
        )
        frame.grid(row=1, column=0, sticky="nsew")

    def _load_users(self) -> None:
        from gui.components import striped_rows
        try:
            users = self.services.auth.list_users()
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")
            return
        striped_rows(self.users_tree, [
            (u.id, (u.id, u.username, u.role, "yes" if u.is_active else "no",
                    humanize_timestamp(u.created_at),
                    humanize_timestamp(u.last_login_at) if u.last_login_at else "—",
                    u.failed_attempts), [])
            for u in users
        ])
        self.users_summary.configure(text=f"{len(users)} account(s)")

    def _selected_user_id(self) -> int | None:
        iid = self.users_tree.focus() if hasattr(self, "users_tree") else None
        return int(iid) if iid and iid.isdigit() else None

    def _reset_password(self) -> None:
        uid = self._selected_user_id()
        if uid is None:
            self.notify("Select a user first.", "warning")
            return
        new_password = simpledialog.askstring(
            "Reset password", "New password (min 8 chars, mixed case + digit/symbol):",
            show="●", parent=self)
        if not new_password:
            return
        try:
            self.services.auth.reset_user_password(uid, new_password)
        except CyberSecError as exc:
            self.show_error("User management", exc.user_message)
            return
        self.notify("Password reset; the user's sessions were revoked.", "success")
        self._load_users()

    def _toggle_active(self) -> None:
        uid = self._selected_user_id()
        if uid is None:
            self.notify("Select a user first.", "warning")
            return
        users = self.services.auth.list_users()
        target = next((u for u in users if u.id == uid), None)
        if target is None:
            return
        try:
            self.services.auth.set_user_active(uid, not target.is_active)
        except CyberSecError as exc:
            self.show_error("User management", exc.user_message)
            return
        self._load_users()

    def _change_role(self) -> None:
        uid = self._selected_user_id()
        if uid is None:
            self.notify("Select a user first.", "warning")
            return
        try:
            self.services.auth.set_user_role(uid, self.role_choice.get())
        except CyberSecError as exc:
            self.show_error("User management", exc.user_message)
            return
        self.notify(f"Role updated to '{self.role_choice.get()}'.", "success")
        self._load_users()

    # -------------------------------------------------------------- account tab

    def _build_account_tab(self) -> None:
        tab = self.tab_account
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        holder = ttk.Frame(tab, style="TFrame")
        holder.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        holder.grid_columnconfigure(0, weight=1)

        user = self.current_user
        info_card = card(holder)
        info_card.grid(row=0, column=0, sticky="ew")
        info_card.grid_columnconfigure(1, weight=1)
        ttk.Label(info_card, text="MY ACCOUNT", style="CardMuted.TLabel",
                  font=font(9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        if user is not None:
            for i, (label, value) in enumerate(
                    (("Username", user.username), ("Role", user.role.upper()),
                     ("Created", humanize_timestamp(user.created_at)),
                     ("Last login", humanize_timestamp(user.last_login_at)
                      if user.last_login_at else "first session")),
                    start=1):
                ttk.Label(info_card, text=label, style="CardMuted.TLabel").grid(
                    row=i, column=0, sticky="w", padx=(0, 16), pady=2)
                ttk.Label(info_card, text=value, style="Card.TLabel").grid(
                    row=i, column=1, sticky="w", pady=2)

        pw_card = card(holder)
        pw_card.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        pw_card.grid_columnconfigure(1, weight=1)
        ttk.Label(pw_card, text="CHANGE PASSWORD", style="CardMuted.TLabel",
                  font=font(9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        self.current_pw = ttk.Entry(pw_card, show="●", width=26)
        self.new_pw = ttk.Entry(pw_card, show="●", width=26)
        self.confirm_pw = ttk.Entry(pw_card, show="●", width=26)
        for i, (label, widget) in enumerate(
                (("Current password", self.current_pw), ("New password", self.new_pw),
                 ("Confirm new password", self.confirm_pw)), start=1):
            ttk.Label(pw_card, text=label, style="Card.TLabel").grid(
                row=i, column=0, sticky="w", padx=(0, 16), pady=3)
            widget.grid(row=i, column=1, sticky="w", pady=3)
        ttk.Button(pw_card, text="Update password", style="Primary.TButton",
                   command=self._change_password).grid(row=4, column=1, sticky="w", pady=(10, 0))

    def _change_password(self) -> None:
        current = self.current_pw.get()
        new = self.new_pw.get()
        confirm = self.confirm_pw.get()
        if new != confirm:
            self.show_error("Account", "New passwords do not match.")
            return
        try:
            self.services.auth.change_password(current, new)
        except CyberSecError as exc:
            self.show_error("Account", exc.user_message)
            return
        self.current_pw.delete(0, "end")
        self.new_pw.delete(0, "end")
        self.confirm_pw.delete(0, "end")
        messagebox.showinfo("Account", "Password updated successfully.", parent=self)
        self.notify("Password updated.", "success")

    # ------------------------------------------------------------------ refresh

    def on_show(self) -> None:
        cfg = self.services.config
        for attr, var in self._field_vars.items():
            value = getattr_nested(cfg, attr, None)
            if value is not None:
                var.set(str(value))
        if hasattr(self, "users_tree"):
            self._load_users()

    # keep notebook tabs fresh when returning
    def refresh(self) -> None:
        self.on_show()


def getattr_nested(obj, dotted: str, default=None):
    parts = dotted.split(".")
    current = obj
    for part in parts:
        current = getattr(current, part, None)
        if current is None:
            return default
    return current
