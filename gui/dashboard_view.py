"""Security dashboard: live KPI cards, severity chart, recent activity."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core.constants import Severity
from core.utils import humanize_timestamp, truncate
from gui.components import (
    PALETTE,
    SEVERITY_HEX,
    BaseView,
    StatCard,
    configure_severity_tags,
    font,
    make_treeview,
    striped_rows,
)


class DashboardView(BaseView):
    view_title = "Security Dashboard"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ---------------------------------------------------------- KPI row
        kpis = ttk.Frame(self, style="TFrame")
        kpis.grid(row=0, column=0, sticky="ew")
        for i in range(4):
            kpis.grid_columnconfigure(i, weight=1, uniform="kpi")

        self.card_scans = StatCard(kpis, "Scans (total / today)", PALETTE["accent"])
        self.card_alerts = StatCard(kpis, "Open alerts", PALETTE["critical"])
        self.card_events = StatCard(kpis, "Security events (24h)", PALETTE["info"])
        self.card_reports = StatCard(kpis, "Reports generated", PALETTE["success"])
        for i, cardw in enumerate((self.card_scans, self.card_alerts,
                                   self.card_events, self.card_reports)):
            cardw.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))

        # ------------------------------------------------- severity + sources
        middle = ttk.Frame(self, style="TFrame")
        middle.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        middle.grid_columnconfigure(0, weight=3)
        middle.grid_columnconfigure(1, weight=2)

        sev_card = ttk.Frame(middle, style="Card.TFrame", padding=(16, 12))
        sev_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        ttk.Label(sev_card, text="EVENTS BY SEVERITY · LAST 7 DAYS",
                  style="CardMuted.TLabel", font=font(9, "bold")).pack(anchor="w")
        self.sev_canvas = tk.Canvas(sev_card, height=120, background=PALETTE["card"],
                                    highlightthickness=0)
        self.sev_canvas.pack(fill="both", expand=True, pady=(8, 0))
        self._last_severity: dict[str, int] = {}
        self.sev_canvas.bind("<Configure>", self._on_canvas_resize)

        sources_card = ttk.Frame(middle, style="Card.TFrame", padding=(16, 12))
        sources_card.grid(row=0, column=1, sticky="nsew")
        ttk.Label(sources_card, text="TOP EVENT SOURCES · 7 DAYS",
                  style="CardMuted.TLabel", font=font(9, "bold")).pack(anchor="w")
        self.sources_lbl = ttk.Label(sources_card, text="—", style="Card.TLabel",
                                     font=font(10, mono=True), justify="left",
                                     wraplength=0, anchor="nw")
        self.sources_lbl.pack(anchor="w", pady=(8, 0), fill="both", expand=True)

        # ------------------------------------------------------- activity row
        bottom = ttk.Frame(self, style="TFrame")
        bottom.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        bottom.grid_columnconfigure(0, weight=3)
        bottom.grid_columnconfigure(1, weight=3)
        bottom.grid_rowconfigure(0, weight=1)

        left = ttk.Frame(bottom, style="TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        head1 = ttk.Frame(left, style="TFrame")
        head1.pack(fill="x", pady=(0, 6))
        ttk.Label(head1, text="RECENT SCANS", style="Muted.TLabel", font=font(9, "bold")).pack(side="left")
        ttk.Button(head1, text="Open scanner →", style="Ghost.TButton",
                   command=lambda: self.app.show_view("scanner")).pack(side="right")
        scans_frame, self.scans_tree = make_treeview(
            left,
            [("id", "#", 44, "w"), ("target", "Target", 150, "w"),
             ("spec", "Ports", 130, "w"), ("open", "Open", 60, "center"),
             ("status", "Status", 90, "w"), ("time", "Started", 130, "w")],
            height=6,
        )
        scans_frame.pack(fill="both", expand=True)
        configure_severity_tags(self.scans_tree)

        right = ttk.Frame(bottom, style="TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        head2 = ttk.Frame(right, style="TFrame")
        head2.pack(fill="x", pady=(0, 6))
        ttk.Label(head2, text="LATEST ALERTS", style="Muted.TLabel", font=font(9, "bold")).pack(side="left")
        ttk.Button(head2, text="Open alerts →", style="Ghost.TButton",
                   command=lambda: self.app.show_view("alerts")).pack(side="right")
        alerts_frame, self.alerts_tree = make_treeview(
            right,
            [("id", "#", 44, "w"), ("severity", "Severity", 90, "w"),
             ("title", "Alert", 210, "w"), ("source", "Source", 110, "w"),
             ("status", "Status", 110, "w")],
            height=6,
        )
        alerts_frame.pack(fill="both", expand=True)
        configure_severity_tags(self.alerts_tree)
        self.alerts_tree.bind("<Double-1>", self._open_alert)

        # quick actions
        quick = ttk.Frame(self, style="TFrame")
        quick.grid(row=3, column=0, sticky="ew", pady=(16, 0))
        for label, view in (("Run a scan", "scanner"), ("Analyze a password", "password"),
                            ("Browse logs", "logs"), ("Generate report", "reports")):
            if self.app.services.auth.has_permission(
                    {"scanner": "scan.run", "password": "password.analyze",
                     "logs": "logs.view", "reports": "reports.view"}[view]):
                ttk.Button(quick, text=label, style="TButton",
                           command=lambda v=view: self.app.show_view(v)).pack(side="left", padx=(0, 10))

    # ------------------------------------------------------------------ data

    def on_show(self) -> None:
        self.refresh()
        self._subscribe_live()

    def refresh(self) -> None:
        s = self.services
        try:
            dash = s.threat.dashboard_stats()
            scan_stats = s.scan.stats()
            report_stats = s.report.stats()
        except Exception as exc:  # noqa: BLE001
            self.app.status(f"Dashboard data unavailable: {exc}", "error")
            return

        self.card_scans.set_value(f"{scan_stats['total']} / {scan_stats['today']}")
        self.card_alerts.set_value(dash["open_alerts"])
        self.card_events.set_value(dash["events_24h"])
        self.card_reports.set_value(report_stats["count"])

        self._draw_severity(dash.get("severity_7d", {}))
        sources = dash.get("top_sources", [])
        text = "SOURCE                       EVENTS\n" + "\n".join(
            f"{row['source'][:26]:<28}{row['n']:>6}" for row in sources
        ) or "No source activity recorded yet."
        self.sources_lbl.configure(text=text)

        striped_rows(self.scans_tree, [
            (row["id"],
             (row["id"], row["target"], truncate(row["port_spec"], 26),
              row["open_ports"], row["status"], humanize_timestamp(row["started_at"])),
             [row["status"]])
            for row in scan_stats.get("recent", [])
        ])
        striped_rows(self.alerts_tree, [
            (a["id"],
             (a["id"], a["severity"], truncate(a["title"], 40), a["source"], a["status"]),
             [f"sev_{a['severity']}", a["status"]])
            for a in self._recent_alerts()
        ])
        self.app._update_backend_label()

    def _recent_alerts(self):
        try:
            return [a.to_dict() for a in self.services.threat.recent_alerts(self.current_user, 6)]
        except Exception:  # noqa: BLE001 - viewer may lack permission mid-logout
            return []

    # ------------------------------------------------------------------ drawing

    def _on_canvas_resize(self, _event=None) -> None:
        """Redraw the chart once the canvas has its real size."""
        if self._last_severity:
            self._draw_severity(self._last_severity)

    def _draw_severity(self, severity: dict[str, int]) -> None:
        self._last_severity = dict(severity)
        canvas = self.sev_canvas
        canvas.delete("all")
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width < 50 or height < 50:
            return  # not mapped yet; <Configure> will redraw
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        counts = [severity.get(s.value, 0) for s in order]
        peak = max(counts + [1])

        bar_area_w = width - 170
        slot = bar_area_w / len(order)
        baseline = height - 26
        for i, (sev, count) in enumerate(zip(order, counts)):
            color = SEVERITY_HEX[sev]
            x0 = 90 + i * slot + 8
            x1 = x0 + slot - 16
            bar_h = int((count / peak) * (baseline - 14)) if count else 0
            canvas.create_rectangle(x0, baseline - bar_h, x1, baseline,
                                    fill=color, width=0)
            canvas.create_text((x0 + x1) / 2, baseline - bar_h - 8, text=str(count),
                               fill=PALETTE["text"], font=font(10, "bold"))
            canvas.create_text((x0 + x1) / 2, baseline + 12, text=sev.value,
                               fill=PALETTE["muted"], font=font(8, "bold"))
        canvas.create_line(84, baseline, width - 10, baseline, fill=PALETTE["border"])

    # ------------------------------------------------------------------ live feed

    def _subscribe_live(self) -> None:
        if getattr(self, "_live_bound", False):
            return
        self._live_bound = True
        self._pending = False

        def on_event(_event) -> None:
            if self._pending:
                return
            self._pending = True

            def do_refresh():
                self._pending = False
                if self._visible():
                    self.refresh()

            self.app.ui(do_refresh)

        self._live_callback = on_event
        self.services.event_processor.subscribe(on_event)

    def on_destroy(self) -> None:
        callback = getattr(self, "_live_callback", None)
        if callback is not None:
            try:
                self.services.event_processor.unsubscribe(callback)
            except Exception:  # noqa: BLE001
                pass

    def _visible(self) -> bool:
        return bool(self.winfo_ismapped())

    def _open_alert(self, _event) -> None:
        iid = self.alerts_tree.focus()
        if iid and iid.isdigit() and self.app.services.auth.has_permission("alerts.view"):
            self.app.show_view("alerts")
