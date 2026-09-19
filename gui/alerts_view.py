"""Threats & alerts interface: filters, alert table, detail pane, lifecycle actions."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core.constants import AlertStatus, Severity
from core.exceptions import CyberSecError
from core.utils import humanize_timestamp, truncate
from gui.components import (
    PALETTE,
    BaseView,
    card,
    configure_severity_tags,
    font,
    make_treeview,
    striped_rows,
)


class AlertsView(BaseView):
    view_title = "Threats & Alerts"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=5)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        # ------------------------------------------------------------- left: table
        left = ttk.Frame(self, style="TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        toolbar = card(left, padding=(12, 10))
        toolbar.grid(row=0, column=0, sticky="ew")
        ttk.Label(toolbar, text="Severity", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.sev_combo = ttk.Combobox(toolbar, state="readonly", width=10,
                                      values=["ALL"] + [s.value for s in Severity])
        self.sev_combo.current(0)
        self.sev_combo.pack(side="left", padx=(0, 14))
        self.sev_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Label(toolbar, text="Status", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.status_combo = ttk.Combobox(toolbar, state="readonly", width=14,
                                         values=["ALL", AlertStatus.OPEN.value,
                                                 AlertStatus.ACKNOWLEDGED.value,
                                                 AlertStatus.RESOLVED.value])
        self.status_combo.current(0)
        self.status_combo.pack(side="left", padx=(0, 14))
        self.status_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        self.search_entry = ttk.Entry(toolbar, width=22)
        self.search_entry.insert(0, "")
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<Return>", lambda _e: self.refresh())

        ttk.Button(toolbar, text="Search", style="TButton",
                   command=self.refresh).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="↻", style="Ghost.TButton", width=3,
                   command=self.refresh).pack(side="left", padx=(6, 0))

        list_card = ttk.Frame(left, style="Card.TFrame", padding=(12, 10))
        list_card.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        list_card.grid_rowconfigure(1, weight=1)
        list_card.grid_columnconfigure(0, weight=1)

        self.counts_lbl = ttk.Label(list_card, text="", style="CardMuted.TLabel")
        self.counts_lbl.grid(row=0, column=0, sticky="w", pady=(0, 6))

        tree_frame, self.alerts_tree = make_treeview(
            list_card,
            [("id", "#", 46, "w"), ("severity", "Severity", 90, "w"),
             ("title", "Alert", 200, "w"), ("source", "Source", 110, "w"),
             ("status", "Status", 110, "w"), ("occ", "×", 40, "center"),
             ("time", "Last seen", 130, "w")],
            height=14,
        )
        tree_frame.grid(row=1, column=0, sticky="nsew")
        configure_severity_tags(self.alerts_tree)
        self.alerts_tree.bind("<<TreeviewSelect>>", self._on_select)

        # ------------------------------------------------------------- right: detail
        right = ttk.Frame(self, style="TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        detail_card = card(right)
        detail_card.grid(row=0, column=0, sticky="nsew")
        detail_card.grid_rowconfigure(1, weight=1)
        detail_card.grid_columnconfigure(0, weight=1)

        self.detail_title = ttk.Label(detail_card, text="Select an alert",
                                      style="CardH2.TLabel", wraplength=320, justify="left")
        self.detail_title.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.detail_text = tk.Text(detail_card, height=10, background=PALETTE["input"],
                                   foreground=PALETTE["text"], relief="flat", wrap="word",
                                   font=font(9, mono=True), padx=10, pady=8,
                                   insertbackground=PALETTE["accent"], state="disabled")
        self.detail_text.grid(row=1, column=0, sticky="nsew")

        action_card = card(right, padding=(12, 10))
        action_card.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        self.ack_btn = ttk.Button(action_card, text="Acknowledge", style="Primary.TButton",
                                  command=self._acknowledge)
        self.ack_btn.pack(side="left")
        self.resolve_btn = ttk.Button(action_card, text="Resolve", style="TButton",
                                      command=self._resolve)
        self.resolve_btn.pack(side="left", padx=(10, 0))
        if not self.app.services.auth.has_permission("alerts.manage"):
            self.ack_btn.state(["disabled"])
            self.resolve_btn.state(["disabled"])

    # ------------------------------------------------------------------ data

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        severity = None if self.sev_combo.get() == "ALL" else self.sev_combo.get()
        status = None if self.status_combo.get() == "ALL" else self.status_combo.get()
        search = self.search_entry.get().strip() or None
        try:
            page = self.services.threat.alerts_page(
                self.current_user, limit=150, severity=severity, status=status, search=search)
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")
            return

        striped_rows(self.alerts_tree, [
            (a.id,
             (a.id, a.severity.value, truncate(a.title, 40), truncate(a.source, 20),
              a.status, f"{a.occurrences}×", humanize_timestamp(a.last_seen_at)),
             [f"sev_{a.severity.value}", a.status])
            for a in page.items
        ])
        try:
            stats = self.services.threat.alert_stats()
        except CyberSecError:
            stats = {}
        by_status = stats.get("by_status", {})
        self.counts_lbl.configure(
            text=f"{page.total} alert(s) — open {by_status.get('OPEN', 0)} · "
                 f"acknowledged {by_status.get('ACKNOWLEDGED', 0)} · "
                 f"resolved {by_status.get('RESOLVED', 0)}")

    # ------------------------------------------------------------------ actions

    def _selected_alert_id(self) -> int | None:
        iid = self.alerts_tree.focus()
        return int(iid) if iid.isdigit() else None

    def _on_select(self, _event=None) -> None:
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        try:
            alert = self.services.threat.get_alert(alert_id)
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")
            return
        color = {"OPEN": PALETTE["danger"], "ACKNOWLEDGED": PALETTE["warning"],
                 "RESOLVED": PALETTE["success"]}.get(alert.status, PALETTE["muted"])
        self.detail_title.configure(text=f"[{alert.severity.value}] {alert.title}",
                                    foreground=color)
        body = (
            f"Alert       #{alert.id}\n"
            f"Severity    {alert.severity.value}\n"
            f"Status      {alert.status}\n"
            f"Source      {alert.source}\n"
            f"Created     {humanize_timestamp(alert.created_at)}\n"
            f"Last seen   {humanize_timestamp(alert.last_seen_at)}\n"
            f"Occurrences {alert.occurrences}\n"
            f"Ack by      {alert.acknowledged_by or '—'} at "
            f"{humanize_timestamp(alert.acknowledged_at) if alert.acknowledged_at else '—'}\n"
            f"Resolved    {humanize_timestamp(alert.resolved_at) if alert.resolved_at else '—'}\n"
            f"\nDESCRIPTION\n{alert.description}\n"
            f"\nDETAILS\n{self._pretty(alert.details)}"
        )
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", body)
        self.detail_text.configure(state="disabled")

    @staticmethod
    def _pretty(details: dict) -> str:
        import json
        try:
            return json.dumps(details, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(details)

    def _acknowledge(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        try:
            self.services.threat.acknowledge_alert(self.current_user, alert_id)
            self.notify(f"Alert #{alert_id} acknowledged.", "success")
        except CyberSecError as exc:
            self.show_error("Alerts", exc.user_message)
            return
        self.refresh()
        self._on_select()

    def _resolve(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        if not self.confirm("Resolve alert", f"Resolve alert #{alert_id}?"):
            return
        try:
            self.services.threat.resolve_alert(self.current_user, alert_id)
            self.notify(f"Alert #{alert_id} resolved.", "success")
        except CyberSecError as exc:
            self.show_error("Alerts", exc.user_message)
            return
        self.refresh()
        self._on_select()
