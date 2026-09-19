"""Network scanner interface: target form, live progress, results table, history."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

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


class ScannerView(BaseView):
    view_title = "Network Scanner"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ------------------------------------------------------------- form
        form_card = card(self, padding=(18, 14))
        form_card.grid(row=0, column=0, sticky="ew")
        form_card.grid_columnconfigure(1, weight=1)
        form_card.grid_columnconfigure(3, weight=1)

        ttk.Label(form_card, text="Target host", style="CardMuted.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8))
        self.target_entry = ttk.Entry(form_card)
        self.target_entry.grid(row=0, column=1, sticky="ew", pady=(0, 8), padx=(0, 16))
        self.target_entry.insert(0, "127.0.0.1")

        ttk.Label(form_card, text="Port preset", style="CardMuted.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 8))
        self.preset_combo = ttk.Combobox(form_card, state="readonly",
                                         values=self.services.scan.port_presets())
        self.preset_combo.current(0)
        self.preset_combo.grid(row=1, column=1, sticky="ew", pady=(0, 8), padx=(0, 16))

        ttk.Label(form_card, text="Custom ports", style="CardMuted.TLabel").grid(
            row=0, column=2, sticky="w", padx=(0, 8))
        self.custom_entry = ttk.Entry(form_card)
        self.custom_entry.grid(row=0, column=3, sticky="ew", pady=(0, 8))
        self.custom_entry.insert(0, "e.g. 22,80,443,8000-8010")

        opts = ttk.Frame(form_card, style="Card.TFrame")
        opts.grid(row=1, column=2, columnspan=2, sticky="ew")
        ttk.Label(opts, text="Timeout s", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.timeout_spin = ttk.Spinbox(opts, from_=0.1, to=10, increment=0.1, width=6)
        self.timeout_spin.set(self.services.config.default_scan_timeout)
        self.timeout_spin.pack(side="left", padx=(0, 16))
        ttk.Label(opts, text="Threads", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.threads_spin = ttk.Spinbox(opts, from_=1, to=128, increment=1, width=6)
        self.threads_spin.set(self.services.config.max_scan_threads)
        self.threads_spin.pack(side="left")

        actions = ttk.Frame(form_card, style="Card.TFrame")
        actions.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        self.start_btn = ttk.Button(actions, text="▶  Start scan", style="Primary.TButton",
                                    command=self._start)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(actions, text="■  Cancel", style="Danger.TButton",
                                     command=self._cancel, state=["disabled"])
        self.cancel_btn.pack(side="left", padx=(10, 0))
        self.progress = ttk.Progressbar(actions, mode="determinate", length=320)
        self.progress.pack(side="left", padx=18, fill="x", expand=True)
        self.progress_lbl = ttk.Label(actions, text="", style="CardMuted.TLabel")
        self.progress_lbl.pack(side="left")

        ttk.Label(actions, text="⚠ Scan only systems you own or are explicitly authorised to test.",
                  style="CardMuted.TLabel", foreground=PALETTE["warning"]).pack(side="right")

        # ---------------------------------------------------------- results
        results_card = ttk.Frame(self, style="Card.TFrame", padding=(16, 12))
        results_card.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
        results_card.grid_rowconfigure(1, weight=1)
        results_card.grid_columnconfigure(0, weight=1)

        head = ttk.Frame(results_card, style="Card.TFrame")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.summary_lbl = ttk.Label(head, text="No scan running.", style="CardH2.TLabel")
        self.summary_lbl.pack(side="left")

        ports_frame, self.ports_tree = make_treeview(
            results_card,
            [("port", "Port", 90, "center"), ("state", "State", 100, "w"),
             ("service", "Service", 130, "w"), ("banner", "Banner", 340, "w"),
             ("latency", "Latency ms", 100, "center")],
            height=9,
        )
        ports_frame.grid(row=1, column=0, sticky="nsew")
        configure_severity_tags(self.ports_tree)
        self.ports_tree.tag_configure("OPEN", foreground=PALETTE["success"])

        # ---------------------------------------------------------- history
        history_card = ttk.Frame(self, style="Card.TFrame", padding=(16, 12))
        history_card.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        history_card.grid_rowconfigure(1, weight=0)
        history_card.grid_columnconfigure(0, weight=1)

        hhead = ttk.Frame(history_card, style="Card.TFrame")
        hhead.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(hhead, text="SCAN HISTORY", style="CardMuted.TLabel",
                  font=font(9, "bold")).pack(side="left")
        ttk.Button(hhead, text="Refresh", style="Ghost.TButton",
                   command=self._load_history).pack(side="right", padx=(8, 0))
        ttk.Button(hhead, text="Load selected result", style="TButton",
                   command=self._load_selected).pack(side="right")

        hist_frame, self.history_tree = make_treeview(
            history_card,
            [("id", "#", 50, "w"), ("target", "Target", 150, "w"),
             ("spec", "Ports", 170, "w"), ("open", "Open", 60, "center"),
             ("total", "Probed", 60, "center"), ("status", "Status", 100, "w"),
             ("user", "By", 90, "w"), ("time", "Started", 140, "w")],
            height=5,
        )
        hist_frame.grid(row=1, column=0, sticky="nsew")
        configure_severity_tags(self.history_tree)
        self.history_tree.bind("<Double-1>", self._load_selected)

        self._active_scan_id: int | None = None
        self._scan_handlers: list = []
        self._load_history()

    # ------------------------------------------------------------------ actions

    def _start(self) -> None:
        target = self.target_entry.get().strip()
        custom = self.custom_entry.get().strip()
        spec = custom if custom and not custom.startswith("e.g.") else self.preset_combo.get()
        if not target:
            self.show_error("Scanner", "Please enter a target host.")
            return
        try:
            timeout = float(self.timeout_spin.get())
            threads = int(self.threads_spin.get())
        except ValueError:
            self.show_error("Scanner", "Timeout and threads must be numeric.")
            return

        self.start_btn.state(["disabled"])
        try:
            scan_id = self.services.scan.start_scan(
                self.current_user, target, spec, timeout=timeout, max_threads=threads)
        except CyberSecError as exc:
            self.start_btn.state(["!disabled"])
            self.show_error("Scan rejected", exc.user_message)
            self.notify(exc.user_message, "error")
            return

        self._active_scan_id = scan_id
        self.cancel_btn.state(["!disabled"])
        self.progress.configure(value=0, maximum=100)
        self.progress_lbl.configure(text="starting…")
        self.summary_lbl.configure(text=f"Scan #{scan_id} running against {target}…")
        self.notify(f"Scan #{scan_id} started against {target}.", "info")
        handler = self._make_update_handler(scan_id)
        self._scan_handlers.append(handler)
        self.services.scan.subscribe_updates(handler)

    def _make_update_handler(self, scan_id: int):
        def handler(updated_id, completed, total, status):
            if updated_id != scan_id:
                return
            self.app.ui(self._apply_update, updated_id, completed, total, status)
        return handler

    def _apply_update(self, scan_id: int, completed: int, total: int, status: str) -> None:
        if total:
            self.progress.configure(maximum=100, value=min(100.0, completed * 100.0 / total))
        self.progress_lbl.configure(text=f"{completed}/{total} ports · {status.lower()}")
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            self.cancel_btn.state(["disabled"])
            self.start_btn.state(["!disabled"])
            try:
                record = self.services.scan.get_scan(scan_id)
            except CyberSecError:
                return
            verb = {"COMPLETED": "finished", "FAILED": "failed", "CANCELLED": "cancelled"}[status]
            kind = {"COMPLETED": "success", "FAILED": "error", "CANCELLED": "warning"}[status]
            if status == "COMPLETED":
                self.summary_lbl.configure(
                    text=f"Scan #{scan_id} — {record.open_ports} open / "
                         f"{record.total_ports} probed on {record.target}")
            else:
                self.summary_lbl.configure(
                    text=f"Scan #{scan_id} {verb}: {record.error or status}")
            self.notify(f"Scan #{scan_id} {verb}.", kind)
            self._show_scan(scan_id)
            self._load_history()

    def _cancel(self) -> None:
        if self._active_scan_id is None:
            return
        try:
            self.services.scan.cancel_scan(self.current_user, self._active_scan_id)
            self.notify(f"Cancellation requested for scan #{self._active_scan_id}.", "warning")
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")

    # ------------------------------------------------------------------ display

    def _show_scan(self, scan_id: int) -> None:
        try:
            record = self.services.scan.get_scan(scan_id)
        except CyberSecError as exc:
            self.show_error("Scanner", exc.user_message)
            return
        rows = []
        for p in record.ports:
            color_tag = "OPEN" if p.state == "OPEN" else ""
            rows.append((f"{scan_id}-{p.port}",
                         (p.port, p.state, p.service or "—",
                          truncate(p.banner, 70) or "—",
                          f"{p.latency_ms:.1f}" if p.latency_ms is not None else "—"),
                         [color_tag]))
        striped_rows(self.ports_tree, rows)

    def _load_history(self) -> None:
        records = self.services.scan.list_scans(limit=40)
        striped_rows(self.history_tree, [
            (r.id,
             (r.id, r.target, truncate(r.port_spec, 30), r.open_ports, r.total_ports,
              r.status, r.username, humanize_timestamp(r.started_at)),
             [r.status])
            for r in records
        ])

    def _load_selected(self, _event=None) -> None:
        iid = self.history_tree.focus()
        if not iid or not iid.isdigit():
            self.notify("Select a scan in the history first.", "warning")
            return
        self._show_scan(int(iid))
        record = self.services.scan.get_scan(int(iid))
        self.summary_lbl.configure(
            text=f"Scan #{record.id} — {record.open_ports} open / "
                 f"{record.total_ports} probed on {record.target}")

    def on_destroy(self) -> None:
        for handler in self._scan_handlers:
            try:
                self.services.scan._update_subscribers.remove(handler)
            except (ValueError, AttributeError):
                pass
        self._scan_handlers.clear()

    def on_show(self) -> None:
        self._load_history()
