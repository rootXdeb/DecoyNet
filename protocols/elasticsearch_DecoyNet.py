"""
Elasticsearch DecoyNet — fake Elastic server on port 9200.

Captures:
- Unauthorized data access attempts
- Index enumeration
- Data exfiltration via search queries
- Cluster reconnaissance
"""

import socket
import time
import json
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)

_FAKE_CLUSTER_INFO = json.dumps({
    "name": "prod-node-01",
    "cluster_name": "corp-elasticsearch",
    "cluster_uuid": "FAKEUUID123456789",
    "version": {"number": "8.9.0", "build_flavor": "default"},
    "tagline": "You Know, for Search"
})

_FAKE_INDICES = json.dumps({
    "corp_users":       {"primaries": {"docs": {"count": 8420}}},
    "financial_data":   {"primaries": {"docs": {"count": 142300}}},
    "customer_records": {"primaries": {"docs": {"count": 95000}}},
    "audit_logs":       {"primaries": {"docs": {"count": 1200000}}},
})


class ElasticsearchDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "ELASTICSEARCH"
    PORT     = 9200

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0      = time.time()
        queries = []

        try:
            conn.settimeout(30)
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                request = data.decode("utf-8", errors="replace")
                lines   = request.split("\r\n")
                first   = lines[0] if lines else ""
                method  = first.split(" ")[0] if first else "GET"
                path    = first.split(" ")[1] if len(first.split(" ")) > 1 else "/"
                queries.append(f"{method} {path}")

                logger.warning("ELASTIC | ip=%-16s %s %s", ip, method, path)

                # Route responses
                if path in ("/", ""):
                    body = _FAKE_CLUSTER_INFO
                elif "_cat/indices" in path or "_stats" in path:
                    logger.warning("ELASTIC INDEX ENUM | ip=%s", ip)
                    body = _FAKE_INDICES
                elif "_search" in path:
                    logger.warning("ELASTIC SEARCH | ip=%s path=%s", ip, path)
                    body = json.dumps({"hits": {"total": {"value": 0}, "hits": []}})
                elif "_delete_by_query" in path:
                    logger.warning("ELASTIC DELETE ATTEMPT | ip=%s", ip)
                    body = json.dumps({"error": "security_exception", "status": 403})
                else:
                    body = json.dumps({"error": "index_not_found_exception", "status": 404})

                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"X-elastic-product: Elasticsearch\r\n\r\n"
                    f"{body}"
                )
                conn.sendall(response.encode())

                if len(queries) > 20:
                    break

        except Exception as exc:
            logger.debug("Elasticsearch session [%s]: %s", ip, exc)

        duration = time.time() - t0
        exfil    = sum(1 for q in queries if "_search" in q or "_cat" in q)
        features = {
            "command_count": len(queries), "recon_count": len(queries),
            "lateral_count": 0, "exploit_count": 0,
            "exfil_count": exfil, "attacker_type": "unknown",
            "mean_delay": 0.2, "stdev_delay": 0.1, "mean_inter": 0.2,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(queries),
                          score["score"], score["level"], "unknown",
                          "Elasticsearch Data Theft" if exfil else "Elasticsearch Probe")
