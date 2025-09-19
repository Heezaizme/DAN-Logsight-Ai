# main.py
from modules.wazuh_connector import fetch_recent_alerts
from modules.analyzer import analyze_log
from modules.correlator import correlate_logs
import subprocess

def main():
    print("🚀 DAN LogSight AI: Starting Full Analysis Pipeline...")
    raw_logs = fetch_recent_alerts(limit=10)
    if not raw_logs:
        print("❌ No logs fetched. Check Wazuh connection.")
        return

    analyzed_logs = [analyze_log(log) for log in raw_logs]
    incidents = correlate_logs(analyzed_logs)
    print(f"[✅] Created {len(incidents)} incidents")

    print("🎯 Launching DAN LogSight AI Desktop App...")
    subprocess.run(["python", "app.py"])

if __name__ == "__main__":
    main()