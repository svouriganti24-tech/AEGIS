"""GUI toolkit: dark "security console" theme, shared widgets and BaseView."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont

from core.constants import Severity, UI_THEME

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

PALETTE = {
    "bg":        "#0B1220",
    "panel":     "#101A2E",
    "card":      "#16213A",
    "card_hi":   "#1B2947",
    "border":    "#24365C",
    "input":     "#0D1526",
    "text":      "#E4ECF7",
    "muted":     "#8CA3C7",
    "accent":    "#22D3EE",
    "accent_hi": "#67E8F9",
    "accent_fg": "#062028",
    "success":   "#34D399",
    "warning":   "#FBBF24",
    "orange":    "#FB923C",
    "danger":    "#F87171",
    "critical":  "#EF4444",
    "info":      "#60A5FA",
}

SEVERITY_HEX = {
    Severity.INFO: PALETTE["info"],
    Severity.LOW: PALETTE["success"],
    Severity.MEDIUM: PALETTE["warning"],
    Severity.HIGH: PALETTE["orange"],
    Severity.CRITICAL: PALETTE["critical"],
}

_FONT_FAMILY = "Helvetica"
_MONO_FAMILY = "Courier"


def setup_fonts() -> None:
    """Choose the best available font families for the platform."""
    global _FONT_FAMILY, _MONO_FAMILY
    families = set(tkfont.families())
    for candidate in ("Segoe UI", "SF Pro Text", "Ubuntu", "DejaVu Sans", "Noto Sans", "Helvetica"):
        if candidate in families:
            _FONT_FAMILY = candidate
            break
    for candidate in ("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Courier New"):
        if candidate in families:
            _MONO_FAMILY = candidate
            break


def font(size: int = 10, weight: str = "normal", *, mono: bool = False, slant: str = "roman") -> tuple:
    family = _MONO_FAMILY if mono else _FONT_FAMILY
    return (family, size, weight, slant)


def setup_styles() -> ttk.Style:
    """Apply the dark theme to every ttk widget class used by the app."""
    style = ttk.Style()
    style.theme_use(UI_THEME)
    p = PALETTE

    style.configure(".", background=p["bg"], foreground=p["text"], borderwidth=0,
                    focuscolor=p["accent"])
    style.configure("TFrame", background=p["bg"])
    style.configure("Panel.TFrame", background=p["panel"])
    style.configure("Card.TFrame", background=p["card"], relief="flat")
    style.configure("Sidebar.TFrame", background=p["panel"])
    style.configure("Header.TFrame", background=p["panel"])

    # Labels -------------------------------------------------------------
    style.configure("TLabel", background=p["bg"], foreground=p["text"])
    style.configure("Card.TLabel", background=p["card"], foreground=p["text"])
    style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
    style.configure("CardMuted.TLabel", background=p["card"], foreground=p["muted"])
    style.configure("PanelMuted.TLabel", background=p["panel"], foreground=p["muted"])
    style.configure("H1.TLabel", background=p["bg"], foreground=p["text"], font=font(20, "bold"))
    style.configure("H2.TLabel", background=p["bg"], foreground=p["text"], font=font(13, "bold"))
    style.configure("CardH2.TLabel", background=p["card"], foreground=p["text"], font=font(13, "bold"))
    style.configure("Stat.TLabel", background=p["card"], foreground=p["text"], font=font(24, "bold"))
    style.configure("Accent.TLabel", background=p["bg"], foreground=p["accent"])
    style.configure("HeaderTitle.TLabel", background=p["panel"], foreground=p["text"], font=font(13, "bold"))
    style.configure("HeaderMeta.TLabel", background=p["panel"], foreground=p["muted"], font=font(9))
    for sev, color in SEVERITY_HEX.items():
        style.configure(f"Sev{sev.value}.TLabel", background=p["card"], foreground=color,
                        font=font(9, "bold"))

    # Buttons ------------------------------------------------------------
    style.configure("TButton", background=p["card"], foreground=p["text"], padding=(12, 6),
                    borderwidth=0, font=font(10))
    style.map("TButton",
              background=[("active", p["card_hi"]), ("pressed", p["card_hi"])],
              foreground=[("disabled", p["muted"])])

    style.configure("Primary.TButton", background=p["accent"], foreground=p["accent_fg"],
                    font=font(10, "bold"), padding=(14, 7))
    style.map("Primary.TButton",
              background=[("disabled", p["card"]), ("pressed", p["accent_hi"]), ("active", p["accent_hi"])],
              foreground=[("disabled", p["muted"])])

    style.configure("Danger.TButton", background="#7F1D1D", foreground="#FECACA", padding=(14, 7))
    style.map("Danger.TButton",
              background=[("disabled", p["card"]), ("pressed", "#991B1B"), ("active", "#991B1B")],
              foreground=[("disabled", p["muted"])])

    style.configure("Ghost.TButton", background=p["panel"], foreground=p["muted"], padding=(10, 5))
    style.map("Ghost.TButton",
              background=[("active", p["card_hi"]), ("pressed", p["card_hi"])],
              foreground=[("active", p["text"]), ("disabled", "#3D4F72")])

    style.configure("Nav.TButton", background=p["panel"], foreground=p["muted"],
                    anchor="w", padding=(16, 10), font=font(10), borderwidth=0)
    style.map("Nav.TButton",
              background=[("active", p["card_hi"])],
              foreground=[("active", p["text"])])

    style.configure("NavActive.TButton", background=p["card_hi"], foreground=p["accent"],
                    anchor="w", padding=(16, 10), font=font(10, "bold"), borderwidth=0)
    style.map("NavActive.TButton", background=[("active", p["card_hi"])])

    # Entries / combos / spin / scale ---------------------------------------
    style.configure("TEntry", fieldbackground=p["input"], foreground=p["text"],
                    insertcolor=p["text"], bordercolor=p["border"], lightcolor=p["border"],
                    darkcolor=p["border"], padding=6)
    style.map("TEntry", bordercolor=[("focus", p["accent"])],
              lightcolor=[("focus", p["accent"])], darkcolor=[("focus", p["accent"])])

    style.configure("TCombobox", fieldbackground=p["input"], background=p["card"],
                    foreground=p["text"], arrowcolor=p["accent"], bordercolor=p["border"],
                    lightcolor=p["border"], darkcolor=p["border"], padding=5)
    style.map("TCombobox",
              fieldbackground=[("readonly", p["input"])],
              foreground=[("readonly", p["text"])],
              bordercolor=[("focus", p["accent"])])

    style.configure("TSpinbox", fieldbackground=p["input"], foreground=p["text"],
                    arrowcolor=p["accent"], bordercolor=p["border"], padding=4)
    style.configure("Horizontal.TProgressbar", background=p["accent"], troughcolor=p["input"],
                    bordercolor=p["bg"], lightcolor=p["accent"], darkcolor=p["accent"])
    style.configure("TNotebook", background=p["bg"], borderwidth=0, tabmargins=(0, 4, 0, 0),
                    bordercolor=p["bg"], lightcolor=p["bg"], darkcolor=p["bg"])
    style.configure("TNotebook.Tab", background=p["panel"], foreground=p["muted"],
                    padding=(16, 8), font=font(10), bordercolor=p["border"],
                    lightcolor=p["border"], darkcolor=p["border"])
    style.map("TNotebook.Tab",
              background=[("selected", p["card"])],
              foreground=[("selected", p["accent"])])
    style.configure("TCheckbutton", background=p["card"], foreground=p["text"],
                    focuscolor=p["accent"], indicatorcolor=p["input"],
                    bordercolor=p["border"], lightcolor=p["border"], darkcolor=p["border"])
    style.map("TCheckbutton",
              background=[("active", p["card"])],
              indicatorcolor=[("selected", p["accent"]), ("!selected", p["input"])],
              foreground=[("disabled", p["muted"])])
    style.configure("TScale", background=p["card"], troughcolor=p["input"],
                    bordercolor=p["bg"], lightcolor=p["accent"], darkcolor=p["accent"])

    # Treeview --------------------------------------------------------------
    style.configure("Treeview", background=p["card"], fieldbackground=p["card"],
                    foreground=p["text"], rowheight=26, borderwidth=0, font=font(9))
    style.map("Treeview",
              background=[("selected", p["card_hi"])],
              foreground=[("selected", p["text"])])
    style.configure("Treeview.Heading", background=p["panel"], foreground=p["muted"],
                    font=font(9, "bold"), borderwidth=0, padding=(8, 6))
    style.map("Treeview.Heading", background=[("active", p["card_hi"])])

    # Scrollbars --------------------------------------------------------------
    for scr in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
        style.configure(scr, background=p["card"], troughcolor=p["bg"],
                        bordercolor=p["bg"], lightcolor=p["card"], darkcolor=p["card"],
                        arrowcolor=p["muted"], gripcount=0)
        style.map(scr, background=[("active", p["card_hi"])])

    return style


# ---------------------------------------------------------------------------
# Shared widgets
# ---------------------------------------------------------------------------


class BaseView(ttk.Frame):
    """Common view scaffolding; views are refreshed whenever they are shown."""

    view_title: str = ""

    def __init__(self, master, app):
        super().__init__(master, style="TFrame")
        self.app = app
        self.services = app.services
        self._built = False

    # -- helpers -----------------------------------------------------------

    @property
    def current_user(self):
        return self.services.auth.current_user

    def on_show(self) -> None:
        """Called every time the view becomes visible."""

    def on_destroy(self) -> None:
        """Called before the view is destroyed — unsubscribe backend callbacks here."""

    def build(self) -> None:
        """First-time layout construction (lazy)."""

    def destroy(self) -> None:
        try:
            self.on_destroy()
        except Exception:  # noqa: BLE001 - teardown must never block navigation
            pass
        super().destroy()

    def notify(self, message: str, kind: str = "info") -> None:
        self.app.status(message, kind)

    def confirm(self, title: str, message: str) -> bool:
        return self.app.confirm(title, message)

    def show_error(self, title: str, message: str) -> None:
        self.app.show_error(title, message)


class StatCard(ttk.Frame):
    """Dashboard metric card with a coloured accent bar."""

    def __init__(self, master, caption: str, color: str, initial: str = "0"):
        super().__init__(master, style="Card.TFrame", padding=(14, 12))
        self._color = color
        bar = tk.Frame(self, width=4, background=color)
        bar.pack(side="left", fill="y", padx=(0, 12))
        body = ttk.Frame(self, style="Card.TFrame")
        body.pack(side="left", fill="both", expand=True)
        self.value_lbl = ttk.Label(body, text=initial, style="Stat.TLabel", background=PALETTE["card"],
                                   foreground=color)
        self.value_lbl.pack(anchor="w")
        self.caption_lbl = ttk.Label(body, text=caption, style="CardMuted.TLabel")
        self.caption_lbl.pack(anchor="w")
        self.configure(width=200)

    def set_value(self, value) -> None:
        self.value_lbl.configure(text=str(value))

    def set_color(self, color: str) -> None:
        self.value_lbl.configure(foreground=color)


def make_treeview(parent, columns, *, height: int = 10, selectmode: str = "browse",
                  striped: bool = True) -> tuple[ttk.Frame, ttk.Treeview]:
    """Create a framed, scrollable treeview.

    ``columns``: sequence of (name, heading, width, anchor).
    """
    frame = ttk.Frame(parent, style="Card.TFrame")
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                        height=height, selectmode=selectmode)
    for name, heading, width, anchor in columns:
        tree.heading(name, text=heading)
        tree.column(name, width=width, anchor=anchor, stretch=True)

    vbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vbar.grid(row=0, column=1, sticky="ns")
    hbar.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    if striped:
        tree.tag_configure("odd", background=PALETTE["card"])
        tree.tag_configure("even", background=PALETTE["panel"])
    return frame, tree


def striped_rows(tree: ttk.Treeview, items: list) -> None:
    """Insert ``items`` (list of (iid, values, tags)) with alternating stripes."""
    tree.delete(*tree.get_children())
    for i, (iid, values, tags) in enumerate(items):
        all_tags = ["odd" if i % 2 == 0 else "even"] + list(tags)
        tree.insert("", "end", iid=str(iid), values=values, tags=all_tags)


def severity_tag(severity) -> str:
    return f"sev_{severity.value if isinstance(severity, Severity) else severity}"


def configure_severity_tags(tree: ttk.Treeview) -> None:
    for sev, color in SEVERITY_HEX.items():
        tree.tag_configure(f"sev_{sev.value}", foreground=color)
    tree.tag_configure("OPEN", foreground=PALETTE["danger"])
    tree.tag_configure("ACKNOWLEDGED", foreground=PALETTE["warning"])
    tree.tag_configure("RESOLVED", foreground=PALETTE["success"])
    tree.tag_configure("COMPLETED", foreground=PALETTE["success"])
    tree.tag_configure("FAILED", foreground=PALETTE["danger"])
    tree.tag_configure("RUNNING", foreground=PALETTE["info"])
    tree.tag_configure("CANCELLED", foreground=PALETTE["muted"])


def form_row(parent, row: int, label: str, widget, *, label_style: str = "TLabel") -> int:
    ttk.Label(parent, text=label, style=label_style).grid(
        row=row, column=0, sticky="w", pady=4, padx=(0, 12))
    widget.grid(row=row, column=1, sticky="ew", pady=4)
    return row + 1


def card(parent, padding=(16, 14)) -> ttk.Frame:
    return ttk.Frame(parent, style="Card.TFrame", padding=padding)


def section(parent, title: str) -> ttk.Label:
    return ttk.Label(parent, text=title.upper(), style="Muted.TLabel",
                     font=font(9, "bold"))
