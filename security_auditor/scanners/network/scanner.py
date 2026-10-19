"""Network/port scanner (spec 11).

Authorization-gated: refuses to run unless the user confirmed authorization
AND the target is in the local/private default scope or explicitly listed in
``network.authorized_targets`` (spec 2).  Uses ``nmap -sV`` when present;
otherwise falls back to a pure-Python TCP connect + banner scan so the
platform works on machines without nmap.
"""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET

from security_auditor.apps.audits.utils import target_authorized
from security_auditor.scanners.base import BaseScanner, Evidence, Finding, ScanResult

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 1433, 1521, 2181, 3000,
                3306, 5432, 5672, 6379, 6380, 8000, 8080, 8443, 9090, 9200,
                11211, 15672, 27017, 9092]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 1433: "MSSQL", 1521: "Oracle",
    2181: "Zookeeper", 3000: "HTTP-alt", 3306: "MySQL", 5432: "PostgreSQL",
    5672: "AMQP/RabbitMQ", 6379: "Redis", 6380: "Redis-alt", 8000: "HTTP-alt (Django dev)",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 9090: "Prometheus", 9200: "Elasticsearch",
    11211: "Memcached", 15672: "RabbitMQ-mgmt", 27017: "MongoDB", 9092: "Kafka",
}

DB_PORTS = {1433, 1521, 3306, 5432, 27017, 9200, 9092, 5672, 15672, 2181}
CACHE_PORTS = {6379, 6380, 11211}
LEGACY_PORTS = {21, 23}          # FTP / Telnet
HTTP_PORTS = {80, 8000, 8080, 3000, 9090}
TLS_PORTS = {443, 8443}

PER_PORT_TIMEOUT = 0.8


class NetworkScanner(BaseScanner):
    name = "network"
    description = "Authorized port/service discovery and exposure analysis"
    scan_ports: list[int] = COMMON_PORTS
    scan_all = False

    def run(self, context) -> ScanResult:
        result = ScanResult(scanner=self.name)
        net_cfg = (context.config or {}).get("network", {}) or {}
        targets = [str(t) for t in net_cfg.get("authorized_targets", ["127.0.0.1"])]
        expected_ports = set(net_cfg.get("expected_open_ports", [80, 443]))
        self.scan_all = False
        configured_ports = net_cfg.get("scan_ports", net_cfg.get("ports", "common"))
        if str(configured_ports).lower() in {"all", "full", "1-65535", "1:65535"}:
            if not bool(net_cfg.get("allow_full_port_scan", False)):
                result.status = "SKIPPED"
                result.error = ("full port scan disabled: set network.allow_full_port_scan: true "
                                "only for an explicitly authorized target")
                context.log("WARN", result.error)
                return result
            if not shutil.which("nmap"):
                result.status = "SKIPPED"
                result.error = "full port scan requires nmap; install nmap or use a bounded port list"
                context.log("WARN", result.error)
                return result
            self.scan_all = True
            self.scan_ports = []
        elif isinstance(configured_ports, list):
            self.scan_ports = [int(p) for p in configured_ports]

        if not context.authorization_confirmed:
            result.status = "SKIPPED"
            result.error = ("network scan skipped: explicit authorization confirmation "
                            "required (spec 2)")
            context.log("WARN", result.error)
            return result

        scanned = []
        seen_hosts = set()
        for host in targets:
            ok, reason = target_authorized(host, context.config)
            if not ok:
                result.evidence.append(Evidence(
                    source="network", rule_id="NET-AUTH-001", polarity="info",
                    summary=f"refused to scan {host}: {reason}",
                    location={"target": host}, requirement_ids=[]))
                continue
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            scanned.append(host)
            self._scan_host(context, result, host, expected_ports)

        if not scanned:
            result.status = "SKIPPED"
            result.error = "no authorized targets to scan"
        result.data["targets_scanned"] = scanned
        return result

    # ------------------------------------------------------------------
    def _scan_host(self, context, result: ScanResult, host: str, expected_ports: set):
        ports = self._nmap_scan(host) if shutil.which("nmap") else None
        if ports is None:
            ports = self._python_scan(host)
            method = "python-connect"
        else:
            method = "nmap -sV"

        result.data.setdefault("hosts", {})[host] = {"method": method, "ports": ports}
        open_ports = [p for p in ports if p["state"] == "open"]
        context.log("INFO", f"network scan {host} ({method}): "
                            f"{len(open_ports)} open port(s)")

        result.evidence.append(Evidence(
            source="network", rule_id="SVC-VERSION-001", polarity="ok",
            summary=f"{host} : {len(open_ports)} port(s) ouvert(s) inventorié(s) "
                    f"(méthode {method}).",
            location={"target": host,
                      "ports": [{"port": p["port"], "service": p.get("service"),
                                 "version": p.get("version")} for p in open_ports]},
            requirement_ids=["REQ-111"]))

        for p in ports:
            if p["state"] != "open":
                continue
            port = p["port"]
            service = p.get("service") or SERVICE_NAMES.get(port, "unknown")
            version = p.get("version", "")

            if port in DB_PORTS:
                self._finding(result, "PORT-DB-001", "High",
                              f"{service} port {port} reachable on {host}",
                              f"{service} ({version or 'no version'}) is exposed on {host}:{port}. "
                              "Backing services must not be reachable outside the trusted network.",
                              ["REQ-107"], host, port, service, version)
            elif port in CACHE_PORTS:
                self._finding(result, "PORT-CACHE-001", "High",
                              f"{service} port {port} reachable on {host}",
                              f"{service} ({version or 'no version'}) is exposed on {host}:{port}; "
                              "caches/brokers are typically unauthenticated.",
                              ["REQ-107"], host, port, service, version)
            elif port in LEGACY_PORTS:
                self._finding(result, "PORT-TELNET-001" if port == 23 else "PORT-FTP-001",
                              "High", f"Insecure legacy service {service} on {host}:{port}",
                              f"{service} transmits credentials in cleartext.",
                              ["REQ-109"], host, port, service, version)
            elif port == 22:
                if version and any(version.startswith(f"OpenSSH_{v}") for v in
                                   ("4", "5", "6", "7.0", "7.1", "7.2")):
                    self._finding(result, "PORT-SSH-001", "Medium",
                                  f"Outdated SSH server on {host}",
                                  f"SSH banner {version!r} indicates an old release with known issues.",
                                  ["REQ-110"], host, port, service, version)
                result.evidence.append(Evidence(
                    source="network", rule_id="PORT-SSH-001", polarity="info",
                    summary=f"SSH reachable on {host}:22 ({version or 'version unknown'}). "
                            "Verify key-only auth and hardened configuration.",
                    location={"target": host, "port": 22, "service": "SSH", "version": version},
                    requirement_ids=["REQ-110", "REQ-111"]))
            elif port in TLS_PORTS:
                tls_info = self._probe_tls(host, port)
                if tls_info:
                    proto = tls_info.get("protocol", "")
                    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self._finding(result, "PORT-TLS-001", "Medium",
                                      f"Weak TLS protocol {proto} on {host}:{port}",
                                      "TLS < 1.2 accepted by the service.",
                                      ["REQ-113", "REQ-065"], host, port, service, version)
                    else:
                        result.evidence.append(Evidence(
                            source="network", rule_id="PORT-TLS-001", polarity="ok",
                            summary=f"TLS handshake on {host}:{port} negotiated {proto}.",
                            location={"target": host, "port": port, "service": service,
                                      "version": proto},
                            requirement_ids=["REQ-113"]))
            elif port == 8000:
                if "WSGIServer" in version or "django" in version.lower():
                    self._finding(result, "PORT-DEVSRV-001", "High",
                                  f"Django development server reachable on {host}:8000",
                                  "manage.py runserver is not hardened for production exposure.",
                                  ["REQ-112"], host, port, service, version)
                else:
                    result.evidence.append(Evidence(
                        source="network", rule_id="PORT-DEVSRV-001", polarity="info",
                        summary=f"Service on {host}:8000 ({version or 'unknown'}); confirm it is "
                                "not the Django development server.",
                        location={"target": host, "port": port, "service": service,
                                  "version": version},
                        requirement_ids=["REQ-112"]))

            if port not in expected_ports:
                result.evidence.append(Evidence(
                    source="network", rule_id="PORT-EXTRA-001", polarity="vuln",
                    summary=f"Unexpected open port {port} ({service}) on {host} - justify or close.",
                    location={"target": host, "port": port, "service": service, "version": version},
                    requirement_ids=["REQ-108"]))
                self._finding(result, "PORT-EXTRA-001", "Low",
                              f"Open port {port} ({service}) not in expected baseline",
                              f"{host}:{port} is open but not listed in network.expected_open_ports.",
                              ["REQ-108"], host, port, service, version, severity_override="Low")

        # --- negative ("checked, clean") evidence -------------------------
        # Le scan a réellement testé ces familles de services : dire ce qui a
        # été vérifié et n'a rien donné (sinon l'exigence resterait NOT_TESTED).
        open_numbers = {p["port"] for p in open_ports}
        legacy = sorted(open_numbers & LEGACY_PORTS)
        if not legacy:
            result.evidence.append(Evidence(
                source="network", rule_id="NET-CLEAN-001", polarity="ok",
                summary=f"{host} : aucun service obsolète (telnet/FTP/rlogin...) parmi les "
                        f"{len(ports)} port(s) testé(s).",
                location={"target": host, "scanned_ports": len(ports)},
                requirement_ids=["REQ-109"]))
        if 22 not in open_numbers:
            result.evidence.append(Evidence(
                source="network", rule_id="NET-CLEAN-002", polarity="ok",
                summary=f"{host} : SSH (22) non joignable — pas d'exposition SSH à durcir "
                        "sur cette cible.",
                location={"target": host}, requirement_ids=["REQ-110"]))
        tls_open = sorted(open_numbers & TLS_PORTS)
        if not tls_open:
            result.evidence.append(Evidence(
                source="network", rule_id="NET-CLEAN-003", polarity="ok",
                summary=f"{host} : aucun service TLS/HTTPS exposé parmi les ports testés "
                        f"({len(ports)} testés) — protocoles TLS faibles non applicables ici.",
                location={"target": host, "scanned_ports": len(ports)},
                requirement_ids=["REQ-113", "REQ-065"]))
        db_cache = sorted(open_numbers & (DB_PORTS | CACHE_PORTS))
        if not db_cache:
            result.evidence.append(Evidence(
                source="network", rule_id="NET-CLEAN-004", polarity="ok",
                summary=f"{host} : aucun port de base de données / cache joignable "
                        "(5432, 3306, 6379, 27017...).",
                location={"target": host}, requirement_ids=["REQ-107"]))
        if 8000 not in open_numbers:
            result.evidence.append(Evidence(
                source="network", rule_id="NET-CLEAN-005", polarity="ok",
                summary=f"{host} : le port 8000 n'est pas exposé — serveur de développement "
                        "Django non joignable depuis la cible scannée.",
                location={"target": host},
                requirement_ids=["REQ-112"]))

        # closed/filtered summary
        closed = sum(1 for p in ports if p["state"] == "closed")
        filtered = sum(1 for p in ports if p["state"] == "filtered")
        result.data.setdefault("hosts", {}).setdefault(host, {})["summary"] = {
            "open": len(open_ports), "closed": closed, "filtered": filtered}

    # ------------------------------------------------------------- engines
    def _python_scan(self, host: str) -> list[dict]:
        ports = []
        for port in self.scan_ports:
            state, banner = "closed", ""
            try:
                with socket.create_connection((host, port), timeout=PER_PORT_TIMEOUT) as s:
                    state = "open"
                    s.settimeout(PER_PORT_TIMEOUT)
                    try:
                        banner = s.recv(256).decode("utf-8", "replace").strip()
                    except OSError:
                        banner = ""
                    if not banner and port in HTTP_PORTS:
                        banner = self._http_probe(s)
            except ConnectionRefusedError:
                state = "closed"
            except (TimeoutError, OSError):
                state = "filtered" if state == "closed" else state
            service = SERVICE_NAMES.get(port, "")
            version = self._guess_version(port, banner)
            ports.append({"port": port, "state": state, "service": service,
                          "version": version, "banner": banner[:200]})
        return ports

    @staticmethod
    def _http_probe(sock) -> str:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            data = sock.recv(512).decode("utf-8", "replace")
            return data.split("\r\n\r\n", 1)[0]
        except OSError:
            return ""

    @staticmethod
    def _guess_version(port: int, banner: str) -> str:
        if not banner:
            return ""
        head = banner.splitlines()[0] if banner else ""
        if "SSH-" in banner:
            return head.split(" ")[0] if head else banner[:60]
        if banner.startswith("220") and ("FTP" in banner.upper()):
            return head[:80]
        if "HTTP/" in head:
            server = ""
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
            return f"HTTP ({server})" if server else "HTTP"
        return head[:80]

    def _probe_tls(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=PER_PORT_TIMEOUT) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {"protocol": tls.version()}
        except (ssl.SSLError, OSError):
            return None

    def _nmap_scan(self, host: str) -> list[dict] | None:
        try:
            port_spec = "1-65535" if self.scan_all else ",".join(map(str, self.scan_ports))
            proc = subprocess.run(
                ["nmap", "-sV", "-Pn", "--host-timeout", "90s", "-p",
                 port_spec, "-oX", "-", host],
                capture_output=True, text=True, timeout=150)
            if proc.returncode != 0:
                return None
            root = ET.fromstring(proc.stdout)
            ports = []
            for port_el in root.iter("port"):
                state = port_el.find("state")
                svc = port_el.find("service")
                ports.append({
                    "port": int(port_el.get("portid", "0")),
                    "state": state.get("state") if state is not None else "closed",
                    "service": svc.get("name", "") if svc is not None else "",
                    "version": (svc.get("product", "") + " " + svc.get("version", "")).strip()
                    if svc is not None else "",
                    "banner": "",
                })
            return ports or None
        except (subprocess.TimeoutExpired, ET.ParseError, OSError):
            return None

    # ------------------------------------------------------------- helpers
    def _finding(self, result: ScanResult, rule_id: str, severity: str, title: str,
                 description: str, reqs: list, host: str, port: int, service: str,
                 version: str, severity_override: str | None = None) -> None:
        # baseline deviations need human justification -> review confidence
        confidence = "Medium" if rule_id == "PORT-EXTRA-001" else "Confirmed"
        evidence = Evidence(
            source="network", rule_id=rule_id, polarity="vuln",
            summary=title,
            location={"target": host, "port": port, "service": service, "version": version},
            requirement_ids=list(reqs), confidence=confidence)
        finding = Finding(
            title=title, description=description,
            severity=severity_override or severity, confidence="Confirmed",
            category="Network Exposure", cwe=["CWE-668"], owasp="A05:2021",
            requirement_ids=list(reqs), sources=["network"], evidence_ids=[evidence.id],
            endpoint=f"{host}:{port}",
            proof=f"{host}:{port} open ({service} {version})".strip(),
            remediation="Bind the service to a private interface / firewall it, or close the port.",
            dedup_key=f"net:{rule_id}:{host}:{port}")
        result.evidence.append(evidence)
        result.findings.append(finding)
