"""Main Tkinter application window: theme, navigation, routing, session guard.

Layout::

    ┌────────────────────────────────────────────────────────┐
    │ header: brand | view title            clock | role     │
    ├────────────┬───────────────────────────────────────────┤
    │  sidebar   │  active view (lazy-built, refreshed)      │
    │  nav       │                                           │
    ├────────────┴───────────────────────────────────────────┤
    │ status bar: message                     backend state  │
    └────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime

from core import constants as C
from core.constants import APP_NAME, APP_VERSION, Permissions, Roles, Severity
from core.logger import get_logger
from gui.components import PALETTE, font, setup_fonts, setup_styles

log = get_logger("gui.app")


class CyberSecApp(tk.Tk):
    """Root window and UI controller."""

    def __init__(self, services, config):
        super().__init__()
        self.services = services
        self.config = config
        self.views: dict[str, dict] = {}
        self._current_view = None
        self._current_name: str | None = None
        self._watchdog_job: str | None = None
        self._clock_job: str | None = None
        self._ui_queue: "queue.Queue[tuple]" = queue.Queue()

        setup_fonts()
        self._style = setup_styles()
        self.title(f"{APP_NAME} — Cybersecurity Console")
        self.geometry(f"{C.UI_WINDOW_WIDTH}x{C.UI_WINDOW_HEIGHT}")
        self.minsize(1100, 720)
        self.configure(background=PALETTE["bg"])
        self._set_app_icon()

        self._register_views()
        self._build_layout()
        self._show_login()
        self._start_clock()
        self.after(80, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ meta

    def _set_app_icon(self) -> None:
        try:
            icon = tk.PhotoImage(width=32, height=32)
            icon.put("{#0EA5E9}", to=(8, 8, 24, 24))
            self._icon_ref = icon  # keep a reference (PhotoImage is GC-prone)
            self.iconphoto(True, icon)
        except tk.TclError:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ views

    def _register_views(self) -> None:
        from gui.alerts_view import AlertsView
        from gui.dashboard_view import DashboardView
        from gui.logs_view import LogsView
        from gui.password_view import PasswordView
        from gui.reports_view import ReportsView
        from gui.scanner_view import ScannerView
        from gui.settings_view import SettingsView

        self.views = {
            "dashboard": {"cls": DashboardView, "title": "Security Dashboard",
                          "icon": "◱", "permission": Permissions.VIEW_DASHBOARD},
            "scanner": {"cls": ScannerView, "title": "Network Scanner",
                        "icon": "◈", "permission": Permissions.RUN_SCAN},
            "password": {"cls": PasswordView, "title": "Password Analyzer",
                         "icon": "⚿", "permission": Permissions.ANALYZE_PASSWORD},
            "alerts": {"cls": AlertsView, "title": "Threats & Alerts",
                       "icon": "⚠", "permission": Permissions.VIEW_ALERTS},
            "logs": {"cls": LogsView, "title": "Security Logs",
                     "icon": "▤", "permission": Permissions.VIEW_LOGS},
            "reports": {"cls": ReportsView, "title": "Reports",
                        "icon": "▣", "permission": Permissions.VIEW_REPORTS},
            "settings": {"cls": SettingsView, "title": "Settings & Administration",
                         "icon": "⚙", "permission": Permissions.VIEW_SETTINGS},
        }

    # ------------------------------------------------------------------ layout

    def _build_layout(self) -> None:
        # Single content host; login and workspace swap inside it.
        self.host = ttk.Frame(self, style="TFrame")
        self.host.grid(row=0, column=0, sticky="nsew")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.host.grid_columnconfigure(0, weight=1)
        self.host.grid_rowconfigure(0, weight=1)

        self.login_host = ttk.Frame(self.host, style="TFrame")

        self.workspace = ttk.Frame(self.host, style="TFrame")
        self.workspace.grid_columnconfigure(1, weight=1)
        self.workspace.grid_rowconfigure(1, weight=1)

        self.sidebar = ttk.Frame(self.workspace, style="Sidebar.TFrame", width=C.UI_SIDEBAR_WIDTH)

        self.header = ttk.Frame(self.workspace, style="Header.TFrame", padding=(20, 12))
        self.content = ttk.Frame(self.workspace, style="TFrame")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self._build_header()
        self.content.grid(row=1, column=1, sticky="nsew")
        self._build_statusbar()

    def _build_header(self) -> None:
        for child in self.header.winfo_children():
            child.destroy()
        self.header.grid(row=0, column=1, sticky="ew")

        self.header_title = ttk.Label(self.header, text="Dashboard", style="HeaderTitle.TLabel")
        self.header_title.pack(side="left")

        self.clock_lbl = ttk.Label(self.header, text="", style="HeaderMeta.TLabel")
        self.clock_lbl.pack(side="right", padx=(12, 0))

        self.role_lbl = ttk.Label(self.header, text="", style="HeaderMeta.TLabel")
        self.role_lbl.pack(side="right")

    def _build_statusbar(self) -> None:
        self.statusbar = ttk.Frame(self.workspace, style="Panel.TFrame", padding=(16, 6))
        self.statusbar.grid(row=2, column=1, sticky="ew")
        self.status_lbl = ttk.Label(self.statusbar, text="Ready.", style="PanelMuted.TLabel")
        self.status_lbl.pack(side="left")
        self.backend_lbl = ttk.Label(self.statusbar, text="", style="PanelMuted.TLabel")
        self.backend_lbl.pack(side="right")

    def _start_clock(self) -> None:
        def tick():
            self.clock_lbl.configure(text=datetime.now().strftime("%a %d %b  %H:%M:%S"))
            self._clock_job = self.after(1000, tick)
        tick()

    # ------------------------------------------------------------------ login

    def _show_login(self) -> None:
        self._cancel_watchdog()
        for w in self.workspace.winfo_children():
            w.grid_forget()
        for w in self.login_host.winfo_children():
            w.destroy()
        self.login_host.grid(row=0, column=0, sticky="nsew")

        from gui.login_view import LoginView
        self._current_name = None
        self._current_view = LoginView(self.login_host, self)
        self._current_view.pack(fill="both", expand=True)
        self.status("Sign in to continue.", "info")

    # --------------------------------------------------------------- workspace

    def on_login_success(self) -> None:
        user = self.services.auth.current_user
        if user is None:
            return
        for w in self.login_host.winfo_children():
            w.destroy()
        self.login_host.grid_forget()

        self._build_sidebar()
        self._build_header()
        self.content.grid(row=1, column=1, sticky="nsew")
        self.statusbar.grid(row=2, column=1, sticky="ew")
        self.role_lbl.configure(
            text=f"{user.username} · {user.role.upper()}"
        )
        self.workspace.grid(row=0, column=0, sticky="nsew")
        self._start_watchdog()
        self._update_backend_label()
        self.show_view("dashboard")
        self.status(f"Welcome back, {user.username}.", "success")

    def logout(self, reason: str = "Signed out.") -> None:
        try:
            self.services.auth.logout()
        finally:
            self._cancel_watchdog()
            self._current_view = None
            self._current_name = None
            self._show_login()
            self.status(reason, "info")

    def _build_sidebar(self) -> None:
        for child in self.sidebar.winfo_children():
            child.destroy()
        self.sidebar.grid(row=0, column=0, rowspan=3, sticky="nsw")
        self.sidebar.grid_propagate(False)

        brand = ttk.Frame(self.sidebar, style="Sidebar.TFrame", padding=(18, 18))
        brand.pack(fill="x")
        ttk.Label(brand, text="◤", foreground=PALETTE["accent"], background=PALETTE["panel"],
                  font=font(16, "bold")).pack(side="left", padx=(0, 8))
        name = ttk.Label(brand, text=APP_NAME.split()[0].upper(), style="PanelMuted.TLabel",
                         foreground=PALETTE["text"], font=font(13, "bold"))
        name.pack(side="left")
        ttk.Label(brand, text=f"v{APP_VERSION}", style="PanelMuted.TLabel",
                  font=font(8)).pack(side="right", pady=(6, 0))

        ttk.Frame(self.sidebar, style="Sidebar.TFrame").pack(fill="x")
        tk.Frame(self.sidebar, height=1, background=PALETTE["border"]).pack(fill="x")

        perms = self.services.auth.permissions()
        self._nav_buttons: dict[str, ttk.Button] = {}
        for name_key, meta in self.views.items():
            if meta["permission"] not in perms:
                continue
            btn = ttk.Button(
                self.sidebar, text=f"  {meta['icon']}  {meta['title']}",
                style="Nav.TButton", command=lambda k=name_key: self.show_view(k),
            )
            btn.pack(fill="x", pady=(2, 0))
            self._nav_buttons[name_key] = btn

        spacer = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        spacer.pack(fill="both", expand=True)

        tk.Frame(self.sidebar, height=1, background=PALETTE["border"]).pack(fill="x")
        user = self.services.auth.current_user
        user_box = ttk.Frame(self.sidebar, style="Sidebar.TFrame", padding=(16, 12))
        user_box.pack(fill="x")
        ttk.Label(user_box, text=user.username if user else "", style="PanelMuted.TLabel",
                  foreground=PALETTE["text"], font=font(11, "bold")).pack(anchor="w")
        ttk.Label(user_box, text=(user.role.upper() if user else ""), style="PanelMuted.TLabel",
                  foreground=PALETTE["accent"], font=font(8, "bold")).pack(anchor="w")
        ttk.Button(user_box, text="⏻  Sign out", style="Ghost.TButton",
                   command=self.logout).pack(fill="x", pady=(8, 0))

    def show_view(self, name: str) -> None:
        meta = self.views.get(name)
        if meta is None:
            return
        if not self.services.auth.has_permission(meta["permission"]):
            self.status("You do not have permission to open that module.", "warning")
            return
        if self._current_name == name and self._current_view is not None:
            self._current_view.on_show()
            return

        if self._current_view is not None:
            self._current_view.destroy()

        view = meta["cls"](self.content, self)
        view.build()
        view.grid(row=0, column=0, sticky="nsew", padx=20, pady=16)
        self.content.grid_rowconfigure(0, weight=1)
        self._current_view = view
        self._current_name = name
        self.header_title.configure(text=meta["title"])

        for key, btn in self._nav_buttons.items():
            btn.configure(style="NavActive.TButton" if key == name else "Nav.TButton")
        view.on_show()

    # ------------------------------------------------------------- session guard

    def _start_watchdog(self) -> None:
        self._cancel_watchdog()

        def check():
            if not self.services.auth.validate_session():
                self.logout("Session expired — please sign in again.")
                return
            self._watchdog_job = self.after(C.UI_SESSION_CHECK_SECONDS * 1000, check)
        self._watchdog_job = self.after(C.UI_SESSION_CHECK_SECONDS * 1000, check)

    def _cancel_watchdog(self) -> None:
        if self._watchdog_job is not None:
            try:
                self.after_cancel(self._watchdog_job)
            except Exception:  # noqa: BLE001
                pass
            self._watchdog_job = None

    # ------------------------------------------------------------------ utilities

    def ui(self, fn, *args, **kwargs) -> None:
        """Schedule ``fn`` to run on the UI thread.

        Thread-safe: worker threads must NEVER call Tkinter directly (nor
        ``after()``, which is likewise main-thread-only). Jobs are enqueued
        and drained by a poller that runs inside the Tk event loop.
        """
        self._ui_queue.put((fn, args, kwargs))

    def _drain_ui_queue(self) -> None:
        try:
            while True:
                fn, args, kwargs = self._ui_queue.get_nowait()
                self._safe(fn, args, kwargs)
        except queue.Empty:
            pass
        except tk.TclError:
            return  # window is gone
        try:
            self.after(80, self._drain_ui_queue)
        except tk.TclError:
            pass

    @staticmethod
    def _safe(fn, args, kwargs) -> None:
        try:
            fn(*args, **kwargs)
        except tk.TclError:
            pass
        except Exception:  # noqa: BLE001
            log.exception("UI task failed")

    def status(self, message: str, kind: str = "info") -> None:
        colors = {"info": PALETTE["muted"], "success": PALETTE["success"],
                  "warning": PALETTE["warning"], "error": PALETTE["danger"],
                  "critical": PALETTE["critical"]}
        try:
            self.status_lbl.configure(text=message, foreground=colors.get(kind, PALETTE["muted"]))
        except tk.TclError:
            pass

    def confirm(self, title: str, message: str) -> bool:
        return messagebox.askyesno(title, message, parent=self)

    def show_error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message, parent=self)

    def show_info(self, title: str, message: str) -> None:
        messagebox.showinfo(title, message, parent=self)

    def _update_backend_label(self) -> None:
        processor = self.services.event_processor
        state = "running" if processor.is_running else "stopped"
        self.backend_lbl.configure(
            text=f"event pipeline {state} · queue {processor.queue_depth} · "
                 f"rules {len(self.services.rules_engine.rules())}"
        )

    # ------------------------------------------------------------------ shutdown

    def _on_close(self) -> None:
        if not messagebox.askokcancel("Quit", "Shut down Aegis CyberSuite?", parent=self):
            return
        self._cancel_watchdog()
        if self._clock_job is not None:
            try:
                self.after_cancel(self._clock_job)
            except Exception:  # noqa: BLE001
                pass
        try:
            self.services.shutdown()
        except Exception:  # noqa: BLE001
            log.exception("Service shutdown failed")
        self.destroy()
