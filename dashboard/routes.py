"""
Flask routes — all pages and REST API endpoints.
"""

import os
import json
import time
import logging
from flask import Blueprint, jsonify, render_template, request, send_file, abort

from database.db_manager import DatabaseManager

bp     = Blueprint("dashboard", __name__)
db     = DatabaseManager()
logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "reports"
)

# ── Pages ─────────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return render_template("index.html")

@bp.route("/attacks")
def attacks():
    return render_template("attacks.html")

@bp.route("/clusters")
def clusters():
    return render_template("clusters.html")

@bp.route("/map")
def attack_map():
    return render_template("map.html")

@bp.route("/replay")
def replay():
    return render_template("replay.html")

@bp.route("/reports")
def reports_page():
    return render_template("reports.html")

@bp.route("/api/docs")
def api_docs():
    return render_template("api_docs.html")

# ── Core API ──────────────────────────────────────────────────────────────────

@bp.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())

@bp.route("/api/sessions")
def api_sessions():
    limit = int(request.args.get("limit", 50))
    return jsonify(db.get_recent_sessions(limit))

@bp.route("/api/iocs")
def api_iocs():
    return jsonify(db.get_iocs())

@bp.route("/api/malware")
def api_malware():
    try:
        rows = db.execute(
            "SELECT * FROM malware_captures ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@bp.route("/api/auth_attempts")
def api_auth():
    try:
        rows = db.execute(
            "SELECT * FROM auth_attempts ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@bp.route("/api/threat_timeline")
def api_timeline():
    try:
        rows = db.execute(
            """SELECT CAST(start_time AS INTEGER) AS ts,
               threat_level, threat_score
               FROM sessions ORDER BY start_time DESC LIMIT 200"""
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@bp.route("/api/top_ips")
def api_top_ips():
    try:
        rows = db.execute(
            """SELECT ip, COUNT(*) AS hits, MAX(threat_score) AS max_score
               FROM sessions GROUP BY ip ORDER BY hits DESC LIMIT 20"""
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

@bp.route("/api/attacker_types")
def api_attacker_types():
    try:
        rows = db.execute(
            """SELECT attacker_type, COUNT(*) AS count
               FROM sessions GROUP BY attacker_type"""
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])

# ── Geo / Map API ─────────────────────────────────────────────────────────────

@bp.route("/api/geo_attacks")
def api_geo_attacks():
    try:
        from geoip.geo_lookup import lookup
        rows = db.get_geo_data()
        result = []
        for row in rows[:100]:
            geo = lookup(row["ip"])
            country_code = geo.get("countryCode", "")
            flag = ""
            if country_code and len(country_code) == 2:
                flag = "".join(
                    chr(0x1F1E6 + ord(c) - ord('A'))
                    for c in country_code.upper()
                )
            result.append({
                **row,
                "lat":          geo.get("lat", 0),
                "lon":          geo.get("lon", 0),
                "country":      geo.get("country", "Unknown"),
                "country_code": country_code,
                "country_flag": flag,
                "city":         geo.get("city", "Unknown"),
                "isp":          geo.get("isp", "Unknown"),
            })
        return jsonify(result)
    except Exception as exc:
        logger.error("Geo API error: %s", exc)
        return jsonify([])

# ── Session Replay API ────────────────────────────────────────────────────────

@bp.route("/api/session_replay/<session_id>")
def api_session_replay(session_id):
    try:
        data = db.get_sessions_with_commands(session_id)
        if not data:
            return jsonify({"error": "Session not found"}), 404
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

# ── Report API ────────────────────────────────────────────────────────────────

@bp.route("/api/reports")
def api_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    reports = []
    try:
        for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if fname.endswith(".html") and fname.startswith("report_"):
                date      = fname.replace("report_", "").replace(".html", "")
                json_file = fname.replace(".html", ".json")
                json_path = os.path.join(REPORTS_DIR, json_file)
                summary   = {}
                if os.path.exists(json_path):
                    try:
                        with open(json_path) as f:
                            summary = json.load(f).get("summary", {})
                    except Exception:
                        pass
                reports.append({
                    "date":             date,
                    "filename":         fname,
                    "total_sessions":   summary.get("total_sessions", "—"),
                    "critical_sessions":summary.get("critical_sessions", "—"),
                    "unique_attackers": summary.get("unique_attackers", "—"),
                })
    except Exception as exc:
        logger.error("Report list error: %s", exc)
    return jsonify({"reports": reports})


@bp.route("/api/generate_report", methods=["POST"])
def api_generate_report():
    try:
        from reports.report_generator import ReportGenerator
        report = ReportGenerator().generate(period_hours=24)
        return jsonify({"success": True, "summary": report.get("summary", {})})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@bp.route("/api/ml_evaluation")
def api_ml_evaluation():
    path = os.path.join(REPORTS_DIR, "ml_evaluation.json")
    if not os.path.exists(path):
        return jsonify({
            "error": "No evaluation yet. Run: python3 -m evaluation.ml_evaluation"
        }), 404
    try:
        with open(path) as f:
            return jsonify(json.load(f))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/api/benchmark")
def api_benchmark():
    path = os.path.join(REPORTS_DIR, "benchmark.json")
    if not os.path.exists(path):
        return jsonify({
            "error": "No benchmark yet. Run: python3 -m benchmark.comparison"
        }), 404
    try:
        with open(path) as f:
            return jsonify(json.load(f))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/reports/view/<filename>")
def view_report(filename):
    if ".." in filename or not filename.endswith(".html"):
        abort(404)
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        abort(404)
    with open(path) as f:
        return f.read(), 200, {"Content-Type": "text/html"}


@bp.route("/reports/download/<filename>")
def download_report(filename):
    if ".." in filename:
        abort(404)
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)
