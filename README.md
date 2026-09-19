# Aegis CyberSuite 🛡️

A **sophisticated desktop cybersecurity console** built in pure Python — network
port scanning, password strength analysis, real-time threat detection with an
extensible rules engine, alert management, tamper-evident event logging and
multi-format security reporting, wrapped in a professional dark-themed Tkinter
interface.

**Zero third-party runtime dependencies.** Python 3.10+ standard library only.

---

## Table of Contents

1. [Features](#features)
2. [Quick start](#quick-start)
3. [Default accounts](#default-accounts)
4. [Architecture](#architecture)
5. [Module guide](#module-guide)
6. [The security pipeline](#the-security-pipeline)
7. [Role-based access control](#role-based-access-control)
8. [Security design decisions](#security-design-decisions)
9. [Threading model](#threading-model)
10. [Testing](#testing)
11. [Extending the system](#extending-the-system)
12. [Troubleshooting](#troubleshooting)
13. [Project layout](#project-layout)

---

## Features

| Module | Capabilities |
|---|---|
| **Network Scanner** | Concurrent TCP connect scanning (thread pool), target validation (IPv4/IPv6/hostname), port presets & custom ranges, live progress, cancellation, banner grabbing + HTTP HEAD probes, latency measurement, full history persisted to SQLite |
| **Password Analyzer** | 0–100 scoring model, entropy estimation (bits), character-class diversity, common-password & leetspeak detection, keyboard-walk detection (`qwerty`, `1qaz2wsx`), ascending/descending sequence detection, repeated char/block detection, date-pattern detection, offline + online crack-time estimates, live GUI meter with criteria checklist |
| **Threat Detection** | Sliding-window event buffers per source, 6 built-in rules (brute-force, port sweep, event rate, suspicious keywords, off-hours activity, large attack surface), detection cooldowns, severity escalation |
| **Rules Engine** | Pluggable `SecurityRule` ABC — register new rules in ~15 lines without touching the pipeline; rules are stateless and crash-isolated |
| **Alerts** | Persistent alerts, occurrence de-duplication with automatic severity escalation, acknowledge/resolve lifecycle, observer notifications to the UI |
| **Event Processing** | Background queue worker, non-blocking `submit()`, crash-proof loop, sync mode for tests, live subscribers |
| **Authentication** | PBKDF2-HMAC-SHA256 (200k iterations, per-user salt, constant-time verify), account lockout, session tokens with expiry + sliding refresh, password change, admin reset |
| **Authorization** | Role matrix (admin / analyst / viewer), 14 permissions, enforced in services (not just hidden in the GUI) |
| **Database** | SQLite (WAL mode), single thread-safe connection, 7 tables + indexes, repository pattern — no SQL outside repositories |
| **Reports** | Full-assessment and per-scan reports in HTML / TXT / JSON, auto-generated recommendations (risky ports, brute-force volume, attack surface), export + history |
| **GUI** | Dark "security console" theme, live dashboard KPIs, RBAC-aware navigation, sortable/paginated/filterable logs, session watchdog with auto-logout |

---

## Quick start

```bash
cd cybersecurity_app

# Linux: tkinter is a separate package
sudo apt install python3-tk        # (skip on Windows/macOS)

python main.py                     # GUI — seeds demo data on first run
python main.py --no-seed           # GUI — clean database (still creates 'admin')
python main.py --cli-demo          # text-mode end-to-end pipeline demo
python main.py --db-path ~/aegis.db
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
# or, if pytest is installed:
pytest tests -v
```

> The application is authorised-testing oriented: only scan systems you own or
> have explicit permission to test. Every scan is logged to the audit trail.

---

## Default accounts

Created automatically on first run (change the passwords immediately):

| Account | Password | Role |
|---|---|---|
| `admin` | `Admin@123` | admin — full control, user management, settings |
| `analyst` | `Analyst@123` | analyst — scans, alert triage, reports (demo data only) |
| `viewer` | `Viewer@123` | viewer — read-only dashboards, logs, reports (demo data only) |

Self-registration from the login screen creates **viewer** accounts; an admin
can promote them in *Settings → User Management*.

---

## Architecture

Layered, dependency-inverted design — the GUI knows services, services know the
security engine and repositories, and **nothing above the repository layer ever
writes SQL**:

```
┌──────────────────────────────────────────────────────────────┐
│  gui/            Tkinter views (dark theme, RBAC navigation) │
├──────────────────────────────────────────────────────────────┤
│  services/       Application facades + ServiceRegistry       │
│                  auth · scan · password · threat · report    │
├──────────────────────────────────────────────────────────────┤
│  security/       Domain engines                              │
│    scanner/        port_scanner + models                     │
│    password/       password_analyzer                         │
│    detection/      threat_detector + rules_engine            │
│    alerts/         alert_manager                             │
│    monitoring/     event_processor (async pipeline)          │
├──────────────────────────────────────────────────────────────┤
│  auth/           authentication (PBKDF2, sessions)           │
│                  authorization (roles, permissions)          │
├──────────────────────────────────────────────────────────────┤
│  data/           SQLite + repositories + models + seeding    │
├──────────────────────────────────────────────────────────────┤
│  core/           config · constants · exceptions · logger    │
│                  utils · validators                          │
│  reports/        report_generator (HTML/TXT/JSON)            │
└──────────────────────────────────────────────────────────────┘
```

`main.py` wires the graph once into a `ServiceRegistry` and hands it to the GUI.
`services/shutdown()` reverses startup in order (cancel scans → stop event
pipeline → close database).

---

## Module guide

### `core/`
- **`config.py`** — typed `AppConfig` dataclass, persisted to `data_store/config.json`, env overrides (`CYBERSEC_DB_PATH`, `CYBERSEC_LOG_LEVEL`, `CYBERSEC_NO_SEED`), validated before use.
- **`constants.py`** — the single source of truth: `Severity` (ordered), `ScanStatus`, `AlertStatus`, `Roles`, event taxonomy, permissions, thresholds, palettes.
- **`exceptions.py`** — typed hierarchy (`CyberSecError` root) so each layer catches precisely what it can handle; exceptions carry `user_message` for GUI display.
- **`validators.py`** — the *only* validation authority: usernames, account passwords, scan targets (IP/hostname), port specs (presets, ranges, lists), setting whitelisting, text sanitisation.
- **`logger.py` / `utils.py`** — rotating file logging; ISO-8601 UTC time helpers (lexicographic sort = chronological sort in SQL), humanised durations, JSON helpers.

### `data/`
- **`database.py`** — `DatabaseManager`: one shared connection guarded by an RLock, WAL mode, FK enforcement, schema bootstrap with `schema_meta` versioning, `transaction()` context manager, `execute/query/scalar` primitives.
- **`models/`** — pure dataclasses (`User`, `ScanRecord`, `PortRecord`, `SecurityEvent`, `Alert`, `ReportRecord`, `AppSetting`).
- **`repositories/`** — one repository per aggregate with parameterised SQL only.
- **`seed.py`** — first-run admin + a realistic 7-day demo dataset (users, scans, events, alerts) built through the real repositories.

### `auth/`
- **`authentication.py`** — `PasswordHasher` (PBKDF2-HMAC-SHA256, format `pbkdf2_sha256$iterations$salt$hash`), `SessionStore` (in-memory, thread-safe, sliding expiry), `AuthenticationService` (register/login/lockout/change-password/admin operations with anti-enumeration timing equalisation).
- **`authorization.py`** — `ROLE_PERMISSIONS` matrix, `authorize()`, `@require_permission` decorator.

### `security/`
- **`scanner/port_scanner.py`** — `PortScanner` with `ThreadPoolExecutor`, cooperative cancellation via `threading.Event`, per-port state classification (OPEN / CLOSED / FILTERED), banner + HTTP HEAD probes, typed errors; `scan_ports_sync()` one-shot helper.
- **`password/password_analyzer.py`** — stateless heuristic engine; embedded common-password corpus; produces `PasswordAnalysis` (score, verdict, entropy, findings with penalties, criteria checklist, crack times, recommendations). **Never receives or stores the password in the event log** — only score/verdict/length.
- **`detection/rules_engine.py`** — `SecurityRule` ABC + `EvaluationContext` (recent history, thresholds); built-ins: `BruteForceRule`, `PortSweepRule`, `EventRateRule`, `SuspiciousKeywordRule`, `OffHoursRule`, `OpenPortExposureRule`; `RulesEngine.register()` makes the set extensible.
- **`detection/threat_detector.py`** — per-source sliding-window `EventBuffer`, (rule, source) cooldown suppression, `Detection` output with severity floor from the source event.
- **`alerts/alert_manager.py`** — de-duplication (open alert, same title+source, within window → occurrence++ and escalation every N occurrences), observer subscribers, acknowledge/resolve.
- **`monitoring/event_processor.py`** — background worker consuming a bounded queue: persist → detect → alert → notify UI subscribers; `process_sync()` mirrors the pipeline inline for tests; internal events (alert bookkeeping) bypass detection to prevent loops.

### `services/`
Thin, permission-checked facades: `AuthService` (session state + user admin), `ScanService` (background scans + progress subscribers + stats), `PasswordService`, `ThreatService` (paged reads, alert lifecycle, dashboard stats), `ReportService` (generate/export/delete with file management). `ServiceRegistry` bundles everything with an orderly `shutdown()`.

### `gui/`
- **`components.py`** — dark theme (`setup_styles` over the `clam` base), font picker, `BaseView` lifecycle (`build()` once, `on_show()` per visit), `StatCard`, striped `Treeview` factory, severity tags.
- **`app.py`** — `CyberSecApp`: login ↔ workspace swap, RBAC-filtered sidebar, header clock + role badge, status bar, 30-second session watchdog, thread-safe `ui()` bridge for worker callbacks, graceful shutdown.
- Views: **dashboard** (KPI cards, canvas severity chart, recent scans/alerts, live feed), **scanner** (form + progress + results + history), **password** (debounced live analysis, meter, checklist), **alerts** (filters, detail pane, ack/resolve), **logs** (filters, click-to-sort, pagination, JSON detail popup), **reports** (generation, preview, export, history), **settings** (config tabs, user management, change password).

---

## The security pipeline

```
 User action (GUI) ──► service (permission check, validation)
                              │
                              ▼
                    EventProcessor.submit()          (never blocks)
                              │
                    ┌───────────▼────────────┐
                    │  worker thread (queue) │
                    └───────────┬────────────┘
             persist via EventRepository
                              │
                    ThreatDetector.process()
                    · EventBuffer (per-source window)
                    · RulesEngine.evaluate(event, ctx)
                              │ detections
                    AlertManager.raise_from_detection()
                    · dedupe → occurrences++ → escalation
                    · notify subscribers
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
        SQLite (events, alerts)         live GUI feed
```

A brute-force burst, for example: 6 failed logins from one source within 5
minutes → `BruteForceRule` fires HIGH (CRITICAL at 2× threshold) → a single
alert is raised (not 6) → further bursts within 10 minutes increment
`occurrences` and escalate severity automatically.

---

## Role-based access control

| Permission | admin | analyst | viewer |
|---|:---:|:---:|:---:|
| View dashboard | ✔ | ✔ | ✔ |
| Run / cancel scans | ✔ | ✔ | — |
| Analyze passwords | ✔ | ✔ | ✔ |
| View alerts / logs / reports | ✔ | ✔ | ✔ |
| Manage alerts (ack/resolve) | ✔ | ✔ | — |
| Generate reports | ✔ | ✔ | — |
| Delete reports | ✔ | — | — |
| Manage settings | ✔ | — | — |
| Manage users | ✔ | — | — |

Enforcement lives in the services (`@require_permission` / `auth.require()`),
so the API stays safe even if driven by scripts rather than the GUI.

---

## Security design decisions

- **Password storage** — PBKDF2-HMAC-SHA256, 200,000 iterations (configurable), 16-byte random salt per user, `hmac.compare_digest` verification, login-time equalisation to blunt username enumeration.
- **No plaintext secrets** — the password analyzer logs score/verdict/length only; account passwords exist solely as hashes; session tokens are `secrets.token_urlsafe(32)` and die with the process.
- **Lockout policy** — N failures → timed account lock, surfaced both to the user and to the detection pipeline (`AUTH_LOCKOUT` event).
- **Input validation at one choke point** — GUI convenience checks exist, but services re-validate everything (`validators.py`), including port specs and scan targets; stored text is sanitised (control chars stripped, length-capped).
- **SQL injection** — impossible by construction: every statement is parameterised inside repositories.
- **Least privilege** — RBAC matrix + last-admin protection (cannot demote/disable the final admin), self-registration restricted to viewer.
- **Auditability** — every security-relevant action becomes a persisted event with timestamp, source, severity and JSON details.

---

## Threading model

| Thread | Role |
|---|---|
| Main / Tk thread | All UI work; only this thread touches widgets |
| `scan-<id>` workers | Run `PortScanner`; publish progress via service callbacks |
| `event-processor` | Consumes the event queue; persists + detects + alerts |

Cross-thread rules: worker callbacks are marshalled to the UI with
`app.ui(fn, ...)` (`after(0)`); the GUI never blocks on a scan; SQLite access is
serialised by an RLock behind the single connection; the event queue drops and
counts rather than blocking producers when full.

---

## Testing

`tests/` uses plain `unittest` (pytest-compatible). Database tests use temp
directories; the scanner test binds a real ephemeral socket on localhost.

| File | Covers |
|---|---|
| `test_password.py` | scoring bounds, common/leet detection, sequences, keyboard walks, repetition, criteria, recommendations, crack-time monotonicity |
| `test_scanner.py` | port-spec parsing, target validation, open/closed/filtered classification against a live localhost socket, unresolvable host error, models/statistics |
| `test_detection.py` | every built-in rule (match & non-match), cooldown suppression, event buffer windows, alert dedupe/escalation/ack/resolve |
| `test_auth.py` | hash/verify, register validation & first-admin rule, login success/failure, lockout + expiry, sessions, change password, RBAC matrix, admin guards |
| `test_database.py` | schema, user/scan/event/alert/report/settings repositories, FK cascade, stale-scan recovery, table counts |
| `test_integration.py` | full wiring: bootstrap → login → scan a live port → brute force → alert raised → report generated |

```bash
python -m unittest discover -s tests -v
```

---

## Extending the system

**Add a detection rule** (~15 lines, no pipeline changes):

```python
from security.detection.rules_engine import RuleResult, SecurityRule

class AdminActivityRule(SecurityRule):
    id = "admin-activity"
    name = "Admin panel activity"
    description = "Flags user-management events for review."

    def evaluate(self, event, ctx):
        if event.event_type != "USER_MANAGEMENT":
            return RuleResult.no_match(self)
        return RuleResult(
            rule_id=self.id, rule_name=self.name, matched=True,
            severity="MEDIUM", title="Administrative action",
            description=f"{event.description} (by {event.username})",
        )

# in main.py: rules_engine.register(AdminActivityRule())
```

Other natural extension points: new port presets (`core/validators.py`), new
report renderers (`reports/report_generator.py`), new scanner probes
(`security/scanner/port_scanner.py`), new GUI views (register them in
`gui/app.py::_register_views` with a permission).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ImportError: tkinter` | Install `python3-tk` (Debian/Ubuntu) or use the official CPython installer |
| `python: can't open file 'main.py'` | Run from inside the `cybersecurity_app/` directory so package imports resolve |
| Scans show everything FILTERED | Local firewall/IDS is dropping SYN probes — increase timeout, or target `127.0.0.1` for a smoke test |
| Demo data missing | It only seeds on an empty database; delete `data_store/aegis.db` (fresh start) or run without `--no-seed` |
| Locked out after failed logins | Wait `lockout_minutes` (default 15) or sign in as another admin and reset |
| Logs growing large | `logs/aegis.log` rotates at ~1.5 MB × 5 backups automatically |

---

## Project layout

```
cybersecurity_app/
├── main.py                      # entry point / wiring / CLI demo
├── requirements.txt             # stdlib-only (pytest optional)
├── README.md
├── core/                        # config, constants, exceptions, logger, utils, validators
├── data/
│   ├── database.py              # SQLite manager (WAL, RLock, schema)
│   ├── seed.py                  # first-run admin + demo dataset
│   ├── models/                  # User, ScanRecord, PortRecord, SecurityEvent, Alert, ...
│   └── repositories/            # user, scan, event, alert, report, settings
├── auth/                        # authentication.py, authorization.py
├── security/
│   ├── scanner/                 # port_scanner.py, models.py
│   ├── password/                # password_analyzer.py
│   ├── detection/               # threat_detector.py, rules_engine.py
│   ├── alerts/                  # alert_manager.py
│   └── monitoring/              # event_processor.py
├── services/                    # auth, scan, password, threat, report + ServiceRegistry
├── reports/                     # report_generator.py (HTML/TXT/JSON)
├── gui/                         # app, components + 8 views (dark theme)
└── tests/                       # 6 unittest modules incl. end-to-end integration
```
