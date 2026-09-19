"""Data structures for the scanning engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.constants import PortState, ScanStatus

#: Well-known TCP services used to label open ports.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 79: "finger", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 515: "printer", 540: "uucp",
    554: "rtsp", 587: "smtp-submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1434: "mssql-monitor", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-tls", 3000: "node-dev", 3128: "squid", 3268: "ldap-gc",
    3306: "mysql", 3389: "rdp", 4444: "metasploit-default", 5000: "flask-dev",
    5432: "postgresql", 5555: "adb", 5672: "rabbitmq", 5900: "vnc", 5901: "vnc-1",
    5984: "couchdb", 6379: "redis", 6667: "irc", 8000: "http-dev", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "sonar/es http", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-cl",
    11211: "memcached", 27017: "mongodb", 50000: "db2",
}

#: Ports whose banners can be harvested with a plain HTTP HEAD request.
HTTP_PROBE_PORTS = {80, 81, 88, 591, 2082, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000}


@dataclass
class ScanTarget:
    """A normalised scan request."""

    host: str
    ports: list[int]
    timeout: float = 1.0

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("ScanTarget.host is required")
        self.ports = sorted({int(p) for p in self.ports})

    def to_dict(self) -> dict:
        return {"host": self.host, "ports": list(self.ports), "timeout": self.timeout}


@dataclass
class PortProbeResult:
    port: int
    state: PortState = PortState.CLOSED
    service: str = ""
    banner: str = ""
    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ScanResult:
    """Aggregate outcome of one scan job (engine-level, pre-persistence)."""

    target: str
    resolved_ip: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    status: ScanStatus = ScanStatus.RUNNING
    ports_scanned: int = 0
    results: list[PortProbeResult] = field(default_factory=list)
    error: str | None = None

    @property
    def open_ports(self) -> list[PortProbeResult]:
        return [r for r in self.results if r.state == PortState.OPEN]

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    def statistics(self) -> dict:
        by_state = {state.value: 0 for state in PortState}
        for r in self.results:
            by_state[r.state.value] += 1
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "status": self.status.value,
            "ports_scanned": self.ports_scanned,
            "open": by_state["OPEN"],
            "closed": by_state["CLOSED"],
            "filtered": by_state["FILTERED"],
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error,
        }

    def to_dict(self) -> dict:
        return {
            **self.statistics(),
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds") if self.finished_at else None,
            "results": [r.to_dict() for r in self.results],
        }
