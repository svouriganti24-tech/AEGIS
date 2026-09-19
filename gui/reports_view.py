"""Reports interface: generate, preview, history, export/delete."""

from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, ttk

from core.exceptions import CyberSecError
from core.utils import humanize_timestamp, truncate
from gui.components import PALETTE, BaseView, card, configure_severity_tags, font, make_treeview, striped_rows


class ReportsView(BaseView):
    view_title = "Reports"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ------------------------------------------------------------- generate
        gen_card = card(self, padding=(14, 12))
        gen_card.grid(row=0, column=0, sticky="ew")
        gen_card.grid_columnconfigure(1, weight=1)
        gen_card.grid_columnconfigure(3, weight=1)

        ttk.Label(gen_card, text="Title", style="CardMuted.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8))
        self.title_entry = ttk.Entry(gen_card)
        self.title_entry.insert(0, "Weekly Security Assessment")
        self.title_entry.grid(row=0, column=1, sticky="ew", pady=(0, 8), padx=(0, 16))

        ttk.Label(gen_card, text="Type", style="CardMuted.TLabel").grid(
            row=0, column=2, sticky="w", padx=(0, 8))
        self.type_combo = ttk.Combobox(gen_card, state="readonly", width=18,
                                       values=["FULL_ASSESSMENT", "SCAN_REPORT"])
        self.type_combo.current(0)
        self.type_combo.grid(row=0, column=3, sticky="ew", pady=(0, 8))
        self.type_combo.bind("<<ComboboxSelected>>", self._type_changed)

        ttk.Label(gen_card, text="Period", style="CardMuted.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 8))
        self.period_combo = ttk.Combobox(gen_card, state="readonly", width=18,
                                         values=["Last 1 day", "Last 7 days",
                                                 "Last 30 days", "Last 90 days"])
        self.period_combo.current(1)
        self.period_combo.grid(row=1, column=1, sticky="ew", pady=(0, 8), padx=(0, 16))

        ttk.Label(gen_card, text="Scan", style="CardMuted.TLabel").grid(
            row=1, column=2, sticky="w", padx=(0, 8))
        self.scan_combo = ttk.Combobox(gen_card, state="disabled", width=30)
        self.scan_combo.grid(row=1, column=3, sticky="ew", pady=(0, 8))

        ttk.Label(gen_card, text="Format", style="CardMuted.TLabel").grid(
            row=2, column=0, sticky="w", padx=(0, 8))
        fmt_row = ttk.Frame(gen_card, style="Card.TFrame")
        fmt_row.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(2, 0))
        self.fmt_combo = ttk.Combobox(fmt_row, state="readonly", width=8,
                                      values=["HTML", "TXT", "JSON"])
        self.fmt_combo.current(0)
        self.fmt_combo.pack(side="left")
        ttk.Button(fmt_row, text="⚙ Generate report", style="Primary.TButton",
                   command=self._generate).pack(side="left", padx=(14, 0))

        # ------------------------------------------------------------- preview
        preview_card = ttk.Frame(self, style="Card.TFrame", padding=(14, 12))
        preview_card.grid(row=1, column=0, sticky="nsew", pady=(14, 0))
        preview_card.grid_rowconfigure(1, weight=1)
        preview_card.grid_columnconfigure(0, weight=1)

        phead = ttk.Frame(preview_card, style="Card.TFrame")
        phead.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.preview_title = ttk.Label(phead, text="PREVIEW", style="CardMuted.TLabel",
                                       font=font(9, "bold"))
        self.preview_title.pack(side="left")
        ttk.Button(phead, text="Save as…", style="Ghost.TButton",
                   command=self._export).pack(side="right", padx=(8, 0))
        ttk.Button(phead, text="Open externally", style="Ghost.TButton",
                   command=self._open_externally).pack(side="right")

        self.preview = tk.Text(preview_card, background=PALETTE["input"],
                               foreground=PALETTE["text"], relief="flat", wrap="none",
                               font=font(9, mono=True), padx=12, pady=10,
                               insertbackground=PALETTE["accent"], state="disabled")
        self.preview.grid(row=1, column=0, sticky="nsew")
        ybar = ttk.Scrollbar(preview_card, orient="vertical", command=self.preview.yview)
        ybar.grid(row=1, column=1, sticky="ns")
        self.preview.configure(yscrollcommand=ybar.set)

        # ------------------------------------------------------------- history
        hist_card = ttk.Frame(self, style="Card.TFrame", padding=(14, 12))
        hist_card.grid(row=2, column=0, sticky="nsew", pady=(14, 0))
        hist_card.grid_columnconfigure(0, weight=1)

        hhead = ttk.Frame(hist_card, style="Card.TFrame")
        hhead.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(hhead, text="REPORT HISTORY", style="CardMuted.TLabel",
                  font=font(9, "bold")).pack(side="left")
        ttk.Button(hhead, text="Delete selected", style="Danger.TButton",
                   command=self._delete).pack(side="right", padx=(8, 0))
        ttk.Button(hhead, text="Load selected", style="TButton",
                   command=self._load_selected).pack(side="right")

        hist_frame, self.history_tree = make_treeview(
            hist_card,
            [("id", "#", 46, "w"), ("title", "Title", 230, "w"),
             ("type", "Type", 150, "w"), ("fmt", "Format", 70, "center"),
             ("by", "Generated by", 110, "w"), ("time", "Generated at", 140, "w")],
            height=5,
        )
        hist_frame.grid(row=1, column=0, sticky="nsew")
        configure_severity_tags(self.history_tree)
        self.history_tree.bind("<Double-1>", self._load_selected)

        self._scan_map: dict[str, int] = {}
        self._reload_scans()
        self._load_history()
        self._current_report_id: int | None = None

    # ------------------------------------------------------------------ actions

    def on_show(self) -> None:
        self._reload_scans()
        self._load_history()

    def _type_changed(self, _event=None) -> None:
        if self.type_combo.get() == "SCAN_REPORT":
            self.scan_combo.state(["!disabled"])
        else:
            self.scan_combo.state(["disabled"])

    def _reload_scans(self) -> None:
        records = self.services.scan.list_scans(limit=30)
        self._scan_map = {
            f"#{r.id} — {r.target} ({r.open_ports} open, {humanize_timestamp(r.started_at)})": r.id
            for r in records
        }
        self.scan_combo.configure(values=list(self._scan_map.keys()))
        if self._scan_map:
            self.scan_combo.current(0)

    def _generate(self) -> None:
        title = self.title_entry.get().strip() or "Security Assessment"
        report_type = self.type_combo.get()
        fmt = self.fmt_combo.get()
        period = {"Last 1 day": 1, "Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}.get(
            self.period_combo.get(), 7)
        scan_id = None
        if report_type == "SCAN_REPORT":
            scan_id = self._scan_map.get(self.scan_combo.get())
            if scan_id is None:
                self.show_error("Reports", "Select a scan for the scan report.")
                return
        self.notify("Generating report…", "info")
        try:
            record = self.services.report.generate(
                self.current_user, title, report_type=report_type,
                period_days=period, scan_id=scan_id, content_format=fmt)
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        self.notify(f"Report #{record.id} generated.", "success")
        self._load_history()
        self._select_and_show(record.id)

    def _load_history(self) -> None:
        try:
            records = self.services.report.list_reports(self.current_user)
        except CyberSecError as exc:
            self.notify(exc.user_message, "error")
            return
        striped_rows(self.history_tree, [
            (r.id, (r.id, truncate(r.title, 40), r.report_type, r.content_format,
                    r.generated_by, humanize_timestamp(r.generated_at)), [])
            for r in records
        ])

    def _select_and_show(self, report_id: int) -> None:
        for iid in self.history_tree.get_children():
            if iid == str(report_id):
                self.history_tree.selection_set(iid)
                self.history_tree.see(iid)
                break
        self._show_report(report_id)

    def _load_selected(self, _event=None) -> None:
        iid = self.history_tree.focus()
        if iid.isdigit():
            self._show_report(int(iid))

    def _show_report(self, report_id: int) -> None:
        try:
            record, content = self.services.report.get_report_content(self.current_user, report_id)
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        self._current_report_id = report_id
        self.preview_title.configure(
            text=f"PREVIEW — {record.title} ({record.content_format})")
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        if record.content_format == "HTML":
            # Show a readable text digest in the mono preview.
            import html
            import re
            text = re.sub(r"<style.*?</style>", "", content, flags=re.S)
            text = re.sub(r"<script.*?</script>", "", text, flags=re.S)
            text = re.sub(r"<[^>]+>", " ", text)
            text = html.unescape(text)
            text = re.sub(r"[ \t]+", " ", text)
            text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
            self.preview.insert("1.0", text)
        else:
            self.preview.insert("1.0", content)
        self.preview.configure(state="disabled")

    def _export(self) -> None:
        if self._current_report_id is None:
            self.notify("Generate or select a report first.", "warning")
            return
        try:
            record, _ = self.services.report.get_report_content(self.current_user,
                                                                self._current_report_id)
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        ext = record.content_format.lower()
        destination = filedialog.asksaveasfilename(
            parent=self, title="Export report",
            defaultextension=f".{ext}",
            filetypes=[(record.content_format, f"*.{ext}"), ("All files", "*.*")],
            initialfile=os.path.basename(record.file_path),
        )
        if not destination:
            return
        try:
            exported = self.services.report.export_report(self.current_user,
                                                          self._current_report_id, destination)
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        self.notify(f"Exported to {exported}", "success")

    def _open_externally(self) -> None:
        if self._current_report_id is None:
            self.notify("Generate or select a report first.", "warning")
            return
        try:
            record, _ = self.services.report.get_report_content(self.current_user,
                                                                self._current_report_id)
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        path = record.file_path
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])  # noqa: S603,S607
            else:
                subprocess.Popen(["xdg-open", path])  # noqa: S603,S607
        except OSError:
            self.show_error("Reports", "No application available to open this file type.")

    def _delete(self) -> None:
        iid = self.history_tree.focus()
        if not iid.isdigit():
            self.notify("Select a report first.", "warning")
            return
        if not self.confirm("Delete report", f"Delete report #{iid} and its file?"):
            return
        try:
            self.services.report.delete_report(self.current_user, int(iid))
        except CyberSecError as exc:
            self.show_error("Reports", exc.user_message)
            return
        self.notify(f"Report #{iid} deleted.", "success")
        self._load_history()
