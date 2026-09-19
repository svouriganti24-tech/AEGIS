"""Password analyzer interface: live strength meter, checklist, guidance."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core.utils import truncate
from gui.components import PALETTE, BaseView, card, font

CRITERIA_LABELS = [
    ("length_12_plus", "12+ characters long"),
    ("has_lower", "Contains lowercase letters"),
    ("has_upper", "Contains uppercase letters"),
    ("has_digit", "Contains digits"),
    ("has_special", "Contains symbols"),
    ("no_sequences", "No letter/number sequences"),
    ("no_keyboard_patterns", "No keyboard walks"),
    ("no_repeats", "No repeated chars or blocks"),
    ("not_common", "Not a common password"),
]

VERDICT_COLORS = {
    "CRITICAL": PALETTE["critical"],
    "WEAK": PALETTE["danger"],
    "FAIR": PALETTE["warning"],
    "GOOD": PALETTE["accent"],
    "STRONG": PALETTE["success"],
}


class PasswordView(BaseView):
    view_title = "Password Analyzer"

    def build(self) -> None:
        self.grid_columnconfigure(0, weight=2)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        # ------------------------------------------------------------- input
        left = ttk.Frame(self, style="TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.grid_rowconfigure(3, weight=1)

        input_card = card(left)
        input_card.grid(row=0, column=0, sticky="ew")
        input_card.grid_columnconfigure(0, weight=1)

        ttk.Label(input_card, text="PASSWORD TO ANALYZE", style="CardMuted.TLabel",
                  font=font(9, "bold")).grid(row=0, column=0, sticky="w")
        entry_row = ttk.Frame(input_card, style="Card.TFrame")
        entry_row.grid(row=1, column=0, sticky="ew", pady=(6, 4))
        entry_row.grid_columnconfigure(0, weight=1)
        self.password_entry = ttk.Entry(entry_row, show="●", font=font(12))
        self.password_entry.grid(row=0, column=0, sticky="ew")
        self.show_var = tk.BooleanVar(value=False)
        self.show_check = ttk.Checkbutton(
            entry_row, text="show", variable=self.show_var, style="TCheckbutton",
            command=self._toggle_show)
        self.show_check.grid(row=0, column=1, padx=(8, 0))

        self._debounce_job: str | None = None
        self.password_entry.bind("<KeyRelease>", self._on_change)

        # strength meter
        self.meter = tk.Canvas(input_card, height=34, background=PALETTE["card"],
                               highlightthickness=0)
        self.meter.grid(row=2, column=0, sticky="ew", pady=(10, 2))
        meter_row = ttk.Frame(input_card, style="Card.TFrame")
        meter_row.grid(row=3, column=0, sticky="ew")
        self.score_lbl = ttk.Label(meter_row, text="score —", style="CardMuted.TLabel")
        self.score_lbl.pack(side="left")
        self.verdict_lbl = ttk.Label(meter_row, text="", style="Card.TLabel",
                                     font=font(11, "bold"))
        self.verdict_lbl.pack(side="right")
        self.crack_lbl = ttk.Label(input_card, text="", style="CardMuted.TLabel",
                                   wraplength=320, justify="left")
        self.crack_lbl.grid(row=4, column=0, sticky="w", pady=(8, 0))

        # criteria checklist
        check_card = card(left)
        check_card.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        ttk.Label(check_card, text="SECURITY REQUIREMENTS", style="CardMuted.TLabel",
                  font=font(9, "bold")).pack(anchor="w", pady=(0, 6))
        self.criteria_labels: dict[str, ttk.Label] = {}
        for key, label in CRITERIA_LABELS:
            row = ttk.Frame(check_card, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            icon = ttk.Label(row, text="○", width=2, style="Card.TLabel",
                             foreground=PALETTE["muted"], font=font(10, "bold"))
            icon.pack(side="left")
            text = ttk.Label(row, text=label, style="CardMuted.TLabel")
            text.pack(side="left")
            self.criteria_labels[key] = (icon, text)

        note_card = card(left, padding=(14, 10))
        note_card.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        ttk.Label(note_card, wraplength=330, justify="left", style="CardMuted.TLabel",
                  text="Analyses never store the password — only the score and verdict are "
                       "written to the audit log.").pack(anchor="w")

        # ------------------------------------------------------------- report
        right = ttk.Frame(self, style="TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)
        right.grid_rowconfigure(4, weight=1)

        findings_card = card(right)
        findings_card.grid(row=0, column=0, sticky="ew")
        findings_card.grid_columnconfigure(0, weight=1)
        ttk.Label(findings_card, text="DETECTED WEAKNESSES", style="CardMuted.TLabel",
                  font=font(9, "bold")).pack(anchor="w", pady=(0, 4))
        self.findings_lbl = ttk.Label(findings_card, text="Type a password to begin.",
                                      style="Card.TLabel", wraplength=430, justify="left")
        self.findings_lbl.pack(anchor="w")

        rec_card = card(right)
        rec_card.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        rec_card.grid_columnconfigure(0, weight=1)
        ttk.Label(rec_card, text="RECOMMENDATIONS", style="CardMuted.TLabel",
                  font=font(9, "bold")).pack(anchor="w", pady=(0, 4))
        self.rec_lbl = ttk.Label(rec_card, text="—", style="Card.TLabel",
                                 wraplength=430, justify="left")
        self.rec_lbl.pack(anchor="w")

        entropy_card = card(right)
        entropy_card.grid(row=2, column=0, sticky="nsew", pady=(14, 0))
        entropy_card.grid_columnconfigure(0, weight=1)
        entropy_card.grid_rowconfigure(1, weight=1)
        ttk.Label(entropy_card, text="ANALYSIS DETAILS", style="CardMuted.TLabel",
                  font=font(9, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.details = tk.Text(entropy_card, height=8, background=PALETTE["input"],
                               foreground=PALETTE["text"], relief="flat", wrap="word",
                               font=font(9, mono=True), padx=10, pady=8,
                               insertbackground=PALETTE["accent"], state="disabled")
        self.details.grid(row=1, column=0, sticky="nsew")

        # clear button
        actions = ttk.Frame(self, style="TFrame")
        actions.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        ttk.Button(actions, text="Clear", style="Ghost.TButton",
                   command=self._clear).pack(side="right")
        ttk.Button(actions, text="Analyze now", style="Primary.TButton",
                   command=self._analyze_now).pack(side="right", padx=(0, 10))

    # ------------------------------------------------------------------ logic

    def _toggle_show(self) -> None:
        self.password_entry.configure(show="" if self.show_var.get() else "●")

    def _on_change(self, _event=None) -> None:
        if self._debounce_job is not None:
            try:
                self.after_cancel(self._debounce_job)
            except Exception:  # noqa: BLE001
                pass
        self._debounce_job = self.after(250, self._analyze_now)

    def _clear(self) -> None:
        self.password_entry.delete(0, "end")
        self._analyze_now()

    def _analyze_now(self) -> None:
        self._debounce_job = None
        password = self.password_entry.get()
        try:
            result = self.services.password.analyze(self.current_user, password)
        except Exception as exc:  # noqa: BLE001
            self.notify(str(exc), "error")
            return

        score = result["score"]
        verdict = result["verdict"]
        color = VERDICT_COLORS.get(verdict, PALETTE["muted"])
        self._draw_meter(score, color)
        self.score_lbl.configure(text=f"score {score}/100 · {result['entropy_bits']} bits entropy")
        self.verdict_lbl.configure(text=verdict, foreground=color)
        self.crack_lbl.configure(
            text=f"Offline attack estimate: {result['crack_time_offline']}   ·   "
                 f"Throttled online attack: {result['crack_time_online']}"
        )

        findings = result["findings"]
        if findings:
            self.findings_lbl.configure(text="\n".join(
                f"•  {f['message']}  (−{f['penalty']})" for f in findings),
                foreground=PALETTE["text"])
        else:
            self.findings_lbl.configure(
                text="No weaknesses detected by the heuristics. ✓",
                foreground=PALETTE["success"])

        self.rec_lbl.configure(text="\n".join(f"•  {r}" for r in result["recommendations"]))

        for key, (icon, text_lbl) in self.criteria_labels.items():
            ok = result["criteria"].get(key, False)
            icon.configure(text="✓" if ok else "✗",
                           foreground=PALETTE["success"] if ok else PALETTE["danger"])
            text_lbl.configure(foreground=PALETTE["text"] if ok else PALETTE["muted"])

        classes = result["char_classes"]
        self._set_details(
            f"length            {result['length']}\n"
            f"charset pool      {result['charset_pool']} symbols\n"
            f"entropy           {result['entropy_bits']} bits\n"
            f"lower/upper       {classes.get('lower', 0)} / {classes.get('upper', 0)}\n"
            f"digits/symbols    {classes.get('digits', 0)} / {classes.get('special', 0)}\n"
            f"structure score   {result['component_scores'].get('structure', 0)}\n"
            f"entropy bonus     +{result['component_scores'].get('entropy_bonus', 0)}\n"
            f"penalties         -{result['component_scores'].get('penalties', 0)}\n"
            f"on common list    {'YES' if result['is_common'] else 'no'}\n"
            f"verdict severity  {result['verdict_severity']}"
        )
        self.notify(f"Analysis complete: verdict {verdict} ({score}/100).",
                    "success" if score >= 60 else "warning")

    def _draw_meter(self, score: int, color: str) -> None:
        canvas = self.meter
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        segments = 20
        filled = round(score / 100 * segments)
        pad = 2
        seg_w = (width - pad * 2) / segments
        for i in range(segments):
            x0 = pad + i * seg_w
            seg_color = color if i < filled else PALETTE["input"]
            canvas.create_rectangle(x0, 6, x0 + seg_w - pad, 26,
                                    fill=seg_color, width=0)
        canvas.create_text(width - pad, 34, text="", anchor="e")

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def on_show(self) -> None:
        self.password_entry.focus_set()
