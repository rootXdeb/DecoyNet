"""
Report Scheduler — runs report generation every 24 hours automatically.
Runs as a background thread started from main.py.
"""

import time
import logging
from reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class ReportScheduler:
    def __init__(self, interval_hours: int = 24):
        self.interval = interval_hours * 3600
        self.generator = ReportGenerator()

    def run_loop(self):
        logger.info("Report scheduler started — generating every %dh", self.interval // 3600)
        while True:
            try:
                report = self.generator.generate(period_hours=24)
                logger.info(
                    "Daily report generated | sessions=%d critical=%d unique_ips=%d",
                    report["summary"]["total_sessions"],
                    report["summary"]["critical_sessions"],
                    report["summary"]["unique_attackers"],
                )
            except Exception as exc:
                logger.error("Report generation error: %s", exc)
            time.sleep(self.interval)
