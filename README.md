#!/usr/bin/env python3
"""
monitor_bot.py
Main scheduler and coordinator for checks and alerts.
"""
import os
import time
import logging
import signal
from datetime import datetime, timedelta
from threading import Event

import yaml
import requests
from apscheduler.schedulers.background import BackgroundScheduler

from checks import run_check
from notifier import Notifier

# Configure logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("monitor_bot")

# Load config
CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.yaml")


def load_config(path=CONFIG_PATH):
    with open(path, "r") as fh:
        return yaml.safe_load(fh)


def main():
    config = load_config()
    notifier = Notifier(config.get("notifier", {}))

    # Keep cooldown map to avoid repeated alerts
    last_alert_at = {}  # check_id -> datetime

    scheduler = BackgroundScheduler()
    stop_event = Event()

    def schedule_check(check):
        check_id = check.get("id") or check["name"]
        interval = check.get("interval_seconds", 60)

        def job():
            nonlocal last_alert_at
            try:
                result = run_check(check)
            except Exception as exc:
                log.exception("Exception running check %s: %s", check_id, exc)
                result = {"ok": False, "reason": f"exception: {exc}"}

            if not result.get("ok"):
                cooldown = timedelta(seconds=check.get("alert_cooldown_seconds", 300))
                now = datetime.utcnow()
                last = last_alert_at.get(check_id)
                if last and now - last < cooldown:
                    log.info("Suppressed alert for %s (cooldown)", check_id)
                    return

                # Send alert
                title = f"ALERT: {check.get('name')}"
                body_lines = [
                    f"Check: {check.get('name')}",
                    f"Time: {now.isoformat()}Z",
                    f"Reason: {result.get('reason')}",
                    f"Details: {result.get('details','')}",
                ]
                body = "\n".join(body_lines)
                try:
                    notifier.alert(title, body)
                    last_alert_at[check_id] = now
                    log.info("Alert sent for %s", check_id)
                except Exception:
                    log.exception("Failed to send alert for %s", check_id)
            else:
                log.debug("Check OK: %s", check.get("name"))

        scheduler.add_job(job, "interval", seconds=interval, id=str(check_id), next_run_time=datetime.utcnow())

    # schedule checks
    for c in config.get("checks", []):
        schedule_check(c)
        log.info("Scheduled check %s", c.get("name"))

    scheduler.start()
    log.info("Scheduler started — running checks. Press Ctrl+C to stop.")

    def _shutdown(signum=None, frame=None):
        log.info("Shutting down scheduler...")
        stop_event.set()
        scheduler.shutdown(wait=False)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        # keep alive
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        scheduler.shutdown()
        log.info("Exited.")


if __name__ == "__main__":
    main()# backend
