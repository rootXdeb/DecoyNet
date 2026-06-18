"""
Report Generator — produces daily threat reports in JSON and HTML format.
Run automatically every 24 hours. HTML report can be printed as PDF from browser.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from database.db_manager import DatabaseManager
from config import LOG_DIR

logger = logging.getLogger(__name__)
REPORTS_DIR = os.path.join(LOG_DIR, "reports")


class ReportGenerator:
    def __init__(self):
        self.db = DatabaseManager()
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate(self, period_hours: int = 24) -> dict:
        since    = time.time() - (period_hours * 3600)
        sessions = self._get_sessions(since)
        auths    = self._get_auths(since)
        malware  = self._get_malware(since)
        iocs     = self.db.get_iocs()

        report = {
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "period_hours":    period_hours,
            "summary": {
                "total_sessions":    len(sessions),
                "critical_sessions": sum(1 for s in sessions if s.get("threat_level") == "CRITICAL"),
                "high_sessions":     sum(1 for s in sessions if s.get("threat_level") == "HIGH"),
                "unique_attackers":  len({s["ip"] for s in sessions}),
                "auth_attempts":     len(auths),
                "malware_caught":    len(malware),
                "total_iocs":        len(iocs),
            },
            "top_attacker_ips":     self._top_ips(sessions),
            "attack_type_breakdown":self._type_breakdown(sessions),
            "protocol_breakdown":   self._protocol_breakdown(sessions),
            "top_credentials":      self._top_creds(auths),
            "attack_chains":        self._attack_chains(sessions),
            "iocs":                 [i["value"] for i in iocs[:50]],
            "malware_hashes":       [m.get("sha256","") for m in malware],
            "recommendations":      self._recommendations(sessions),
        }

        # Save JSON report
        date_str  = datetime.now().strftime("%Y-%m-%d")
        json_path = os.path.join(REPORTS_DIR, f"report_{date_str}.json")
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        # Save HTML report
        html_path = os.path.join(REPORTS_DIR, f"report_{date_str}.html")
        with open(html_path, "w") as f:
            f.write(self._render_html(report))

        logger.info("Report generated → %s", json_path)
        return report

    # ── Data collectors ───────────────────────────────────────────────────────

    def _get_sessions(self, since: float) -> list:
        rows = self.db.execute(
            "SELECT * FROM sessions WHERE start_time > ? ORDER BY threat_score DESC",
            (since,)
        ).fetchall()
        return [dict(r) for r in rows]

    def _get_auths(self, since: float) -> list:
        rows = self.db.execute(
            "SELECT * FROM auth_attempts WHERE timestamp > ?", (since,)
        ).fetchall()
        return [dict(r) for r in rows]

    def _get_malware(self, since: float) -> list:
        rows = self.db.execute(
            "SELECT * FROM malware_captures WHERE timestamp > ?", (since,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Analysis helpers ──────────────────────────────────────────────────────

    def _top_ips(self, sessions: list) -> list:
        counts = {}
        for s in sessions:
            ip = s["ip"]
            if ip not in counts:
                counts[ip] = {"ip": ip, "sessions": 0, "max_score": 0}
            counts[ip]["sessions"]  += 1
            counts[ip]["max_score"]  = max(counts[ip]["max_score"], s.get("threat_score", 0))
        return sorted(counts.values(), key=lambda x: x["max_score"], reverse=True)[:10]

    def _type_breakdown(self, sessions: list) -> dict:
        counts = {}
        for s in sessions:
            t = s.get("attacker_type", "unknown")
            counts[t] = counts.get(t, 0) + 1
        return counts

    def _protocol_breakdown(self, sessions: list) -> dict:
        counts = {}
        for s in sessions:
            p = s.get("protocol", "SSH")
            counts[p] = counts.get(p, 0) + 1
        return counts

    def _top_creds(self, auths: list) -> list:
        pairs = {}
        for a in auths:
            key = f"{a.get('username','')}:{a.get('password','')}"
            pairs[key] = pairs.get(key, 0) + 1
        return sorted(
            [{"credential": k, "count": v} for k, v in pairs.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

    def _attack_chains(self, sessions: list) -> list:
        chains = {}
        for s in sessions:
            c = s.get("attack_chain", "")
            if c:
                chains[c] = chains.get(c, 0) + 1
        return sorted(
            [{"chain": k, "count": v} for k, v in chains.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

    def _recommendations(self, sessions: list) -> list:
        recs = []
        critical = sum(1 for s in sessions if s.get("threat_level") == "CRITICAL")
        unique   = len({s["ip"] for s in sessions})

        if critical > 0:
            recs.append(f"URGENT: {critical} CRITICAL sessions detected. Review attacker IPs immediately.")
        if unique > 50:
            recs.append(f"High volume: {unique} unique IPs. Consider geo-blocking high-risk regions.")

        top = self._top_ips(sessions)
        if top:
            recs.append(f"Block top attacker IP: {top[0]['ip']} ({top[0]['sessions']} sessions).")

        recs.append("Rotate all credentials mentioned in attack sessions.")
        recs.append("Check firewall rules — ensure only required ports are exposed.")
        return recs

    # ── HTML renderer ─────────────────────────────────────────────────────────

    def _render_html(self, report: dict) -> str:
        s   = report["summary"]
        gen = report["generated_at"][:19].replace("T", " ")

        top_ips_rows = "".join(
            f"<tr><td>{r['ip']}</td><td>{r['sessions']}</td><td>{r['max_score']}</td></tr>"
            for r in report["top_attacker_ips"]
        )
        cred_rows = "".join(
            f"<tr><td><code>{r['credential']}</code></td><td>{r['count']}</td></tr>"
            for r in report["top_credentials"]
        )
        chain_rows = "".join(
            f"<tr><td>{r['chain']}</td><td>{r['count']}</td></tr>"
            for r in report["attack_chains"]
        )
        recs = "".join(f"<li>{r}</li>" for r in report["recommendations"])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>DecoyNetAI Threat Report — {gen[:10]}</title>
<style>
  body {{font-family:Arial,sans-serif;background:#0f1117;color:#e2e8f0;margin:0;padding:24px}}
  h1   {{color:#3b82f6;border-bottom:2px solid #3b82f6;padding-bottom:8px}}
  h2   {{color:#94a3b8;margin-top:32px}}
  .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:20px 0}}
  .card{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:8px;padding:16px;text-align:center}}
  .card .num{{font-size:2em;font-weight:700;color:#3b82f6}}
  .card.red .num{{color:#ef4444}}
  .card .lbl{{font-size:12px;color:#94a3b8;text-transform:uppercase;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:8px;overflow:hidden}}
  th   {{background:#2a2d3a;padding:10px 14px;text-align:left;font-size:12px;color:#94a3b8;text-transform:uppercase}}
  td   {{padding:10px 14px;border-bottom:1px solid #2a2d3a;font-size:13px}}
  code {{background:#2a2d3a;padding:2px 6px;border-radius:4px;font-size:12px}}
  ul   {{background:#1a1d27;border-radius:8px;padding:20px 20px 20px 40px}}
  li   {{margin-bottom:8px;color:#fbbf24}}
  .footer{{margin-top:40px;color:#4a5568;font-size:12px;text-align:center}}
</style>
</head>
<body>
<h1>🛡 DecoyNetAI — Threat Intelligence Report</h1>
<p style="color:#94a3b8">Generated: {gen} UTC &nbsp;|&nbsp; Period: Last {report['period_hours']} hours</p>

<div class="grid">
  <div class="card"><div class="num">{s['total_sessions']}</div><div class="lbl">Total Sessions</div></div>
  <div class="card red"><div class="num">{s['critical_sessions']}</div><div class="lbl">Critical Threats</div></div>
  <div class="card"><div class="num">{s['unique_attackers']}</div><div class="lbl">Unique Attackers</div></div>
  <div class="card"><div class="num">{s['malware_caught']}</div><div class="lbl">Malware Caught</div></div>
</div>

<h2>Top Attacker IPs</h2>
<table><thead><tr><th>IP Address</th><th>Sessions</th><th>Max Score</th></tr></thead>
<tbody>{top_ips_rows}</tbody></table>

<h2>Top Credential Attempts</h2>
<table><thead><tr><th>Username:Password</th><th>Attempts</th></tr></thead>
<tbody>{cred_rows}</tbody></table>

<h2>Attack Chains Observed</h2>
<table><thead><tr><th>Chain</th><th>Count</th></tr></thead>
<tbody>{chain_rows}</tbody></table>

<h2>IOCs — Attacker IPs</h2>
<p style="font-size:13px;color:#94a3b8">{", ".join(report['iocs'][:20]) or "None yet"}</p>

<h2>Recommendations</h2>
<ul>{recs}</ul>

<div class="footer">DecoyNetAI Adaptive Deception Platform — Confidential Security Report</div>
</body></html>"""
