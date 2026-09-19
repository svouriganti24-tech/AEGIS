"""Security logs interface: filterable, sortable, paginated event table."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk

from core.constants import EVENT_TYPE_GROUPS, Severity
from core.exceptions import CyberSecError
from core.utils import humanize_timestamp, truncate
from gui.components import PALETTE, BaseView, card, configure_severity_tags, font, make_treeview, striped_rows

PAGE_SIZE = 50
SORTABLE = {"timestamp": 0, "severity": 1, "event_type": 2, "source": 3}


class LogsView(BaseView):
    view_title = "Security Logs"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ------------------------------------------------------------- toolbar
        toolbar = card(self, padding=(12, 10))
        toolbar.grid(row=0, column=0, sticky="ew")

        ttk.Label(toolbar, text="Type", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.type_combo = ttk.Combobox(toolbar, state="readonly", width=22, values=["ALL"])
        self.type_combo.current(0)
        self.type_combo.pack(side="left", padx=(0, 14))
        self.type_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Label(toolbar, text="Severity", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.sev_combo = ttk.Combobox(toolbar, state="readonly", width=10,
                                      values=["ALL"] + [s.value for s in Severity])
        self.sev_combo.current(0)
        self.sev_combo.pack(side="left", padx=(0, 14))
        self.sev_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Label(toolbar, text="Source", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.source_entry = ttk.Entry(toolbar, width=16)
        self.source_entry.pack(side="left", padx=(0, 14))
        self.source_entry.bind("<Return>", lambda _e: self.refresh())

        ttk.Label(toolbar, text="Search", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.search_entry = ttk.Entry(toolbar, width=20)
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<Return>", lambda _e: self.refresh())

        ttk.Button(toolbar, text="Apply", style="Primary.TButton",
                   command=self.refresh).pack(side="left", padx=(10, 0))
        ttk.Button(toolbar, text="Reset", style="Ghost.TButton",
                   command=self._reset).pack(side="left", padx=(8, 0))

        # ------------------------------------------------------------- table
        table_card = ttk.Frame(self, style="Card.TFrame", padding=(12, 10))
        table_card.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        table_card.grid_rowconfigure(1, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        self.summary_lbl = ttk.Label(table_card, text="", style="CardMuted.TLabel")
        self.summary_lbl.grid(row=0, column=0, sticky="w", pady=(0, 6))

        tree_frame, self.logs_tree = make_treeview(
            table_card,
            [("timestamp", "Timestamp (UTC)", 150, "w"), ("severity", "Severity", 90, "w"),
             ("event_type", "Event type", 170, "w"), ("source", "Source", 130, "w"),
             ("description", "Description", 430, "w"), ("id", "#", 50, "w")],
            height=16,
        )
        tree_frame.grid(row=1, column=0, sticky="nsew")
        configure_severity_tags(self.logs_tree)
        self.logs_tree.bind("<Double-1>", self._show_details)

        # click-to-sort on headings
        for name in SORTABLE:
            self.logs_tree.heading(name, text=self.logs_tree.heading(name)["text"],
                                   command=lambda n=name: self._toggle_sort(n))

        # ------------------------------------------------------------- pager
        pager = ttk.Frame(self, style="TFrame")
        pager.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        self.prev_btn = ttk.Button(pager, text="← Prev", style="Ghost.TButton",
                                   command=self._prev_page)
        self.prev_btn.pack(side="left")
        self.page_lbl = ttk.Label(pager, text="page 1", style="Muted.TLabel")
        self.page_lbl.pack(side="left", padx=12)
        self.next_btn = ttk.Button(pager, text="Next →", style="Ghost.TButton",
                                   command=self._next_page)
        self.next_btn.pack(side="left")
        ttk.Label(pager, text="double-click a row for full JSON details",
                  style="Muted.TLabel").pack(side="right")

        self.page = 0
        self._sort_key: str | None = None
        self._sort_desc = True
        self._reload_types()

    # ------------------------------------------------------------------ data

    def on_show(self) -> None:
        self._reload_types()
        self.refresh()

    def _reload_types(self) -> None:
        all_types = []
        try:
            all_types = self.services.threat.event_types()
        except CyberSecError:
            pass
        groups = ["ALL", "— grouped —"]
        for group, types in EVENT_TYPE_GROUPS.items():
            present = [t for t in types if not all_types or t in all_types]
            if present:
                groups.append(f"▸ {group}")
        groups.extend(sorted(all_types))
        self.type_combo.configure(values=groups)

    def _resolve_type_filter(self) -> str | None:
        selection = self.type_combo.get()
        if selection in ("ALL", "— grouped —", ""):
            return None
        if selection.startswith("▸ "):
            group = selection[2:]
            for name, types in EVENT_TYPE_GROUPS.items():
                if name == group:
                    # multi-value not supported by one filter; use first type marker
                    return types[0] if len(types) == 1 else None
            return None
        return selection

    def _reset(self) -> None:
        self.type_combo.current(0)
        self.sev_combo.current(0)
        self.source_entry.delete(0, "end")
        self.search_entry.delete(0, "end")
        self.page = 0
        self._sort_key = None
        self.refresh()

    def refresh(self) -> None:
        try:
            page = self.services.threat.events_page(
                self.current_user,
                limit=PAGE_SIZE, offset=self.page * PAGE_SIZE,
                severity=None if self.sev_combo.get() == "ALL" else self.sev_combo.get(),
                event_type=self._resolve_type_filter(),
                source=self.source_entry.get().strip() or None,
                search=self.search_entry.get().strip() or None,
            )
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")
            return

        items = [(e.id,
                  (humanize_timestamp(e.timestamp), e.severity.value, e.event_type,
                   truncate(e.source, 22), truncate(e.description, 90), e.id),
                  [f"sev_{e.severity.value}"])
                 for e in page.items]
        if self._sort_key:
            col = SORTABLE[self._sort_key]
            items.sort(key=lambda t: str(t[1][col]), reverse=self._sort_desc)
        striped_rows(self.logs_tree, items)

        total_pages = max(1, (page.total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_lbl.configure(text=f"page {self.page + 1} / {total_pages} — {page.total} events")
        self.prev_btn.state(["!disabled" if self.page > 0 else "disabled"])
        self.next_btn.state(["!disabled" if page.has_next else "disabled"])
        self.summary_lbl.configure(
            text=f"{page.total} security event(s) match the current filters")

    def _prev_page(self) -> None:
        if self.page > 0:
            self.page -= 1
            self.refresh()

    def _next_page(self) -> None:
        self.page += 1
        self.refresh()

    def _toggle_sort(self, column: str) -> None:
        if self._sort_key == column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_key = column
            self._sort_desc = True
        self.refresh()

    # ------------------------------------------------------------------ detail popup

    def _show_details(self, _event=None) -> None:
        iid = self.logs_tree.focus()
        if not iid or not iid.isdigit():
            return
        page = self.services.threat.events_page(self.current_user, limit=PAGE_SIZE,
                                                offset=self.page * PAGE_SIZE)
        event = next((e for e in page.items if e.id == int(iid)), None)
        if event is None:
            return
        popup = tk.Toplevel(self)
        popup.title(f"Event #{event.id} — {event.event_type}")
        popup.configure(background=PALETTE["card"])
        popup.transient(self.winfo_toplevel())
        popup.geometry("620x460")

        header = tk.Frame(popup, background=PALETTE["panel"])
        header.pack(fill="x")
        tk.Label(header, text=f"Event #{event.id} · {event.event_type}",
                 background=PALETTE["panel"], foreground=PALETTE["accent"],
                 font=font(12, "bold"), padx=14, pady=10).pack(anchor="w")

        body = tk.Text(popup, background=PALETTE["input"], foreground=PALETTE["text"],
                       relief="flat", wrap="word", font=font(9, mono=True),
                       padx=12, pady=10, insertbackground=PALETTE["accent"])
        body.pack(fill="both", expand=True, padx=12, pady=12)
        body.insert("1.0", json.dumps(event.to_dict(), indent=2, ensure_ascii=False, default=str))
        body.configure(state="disabled")
        tk.Button(popup, text="Close", background=PALETTE["card"], fg=PALETTE["text"],
                  activebackground=PALETTE["card_hi"], activeforeground=PALETTE["text"],
                  relief="flat", padx=18, pady=6, command=popup.destroy).pack(pady=(0, 12))
