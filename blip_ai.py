"""
BLIP-AI — Behavioral Log Investigation Platform — Artificial Intelligence
=========================================================================
Main orchestrator. Ties Splunk connector, investigation engine,
and Claude analyst together into a single autonomous SOC investigation loop.

Version: 1.0
Author: Taylor Glass
Repository: github.com/tjglass814/BLIP-AI
"""

import os
import json
import time
from datetime import datetime, timezone
from investigation_engine import InvestigationEngine
from claude_analyst import ClaudeAnalyst

# ANSI colors for terminal output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def print_banner():
    print(f"""
{BLUE}{BOLD}
██████╗ ██╗     ██╗██████╗       █████╗ ██╗
██╔══██╗██║     ██║██╔══██╗     ██╔══██╗██║
██████╔╝██║     ██║██████╔╝     ███████║██║
██╔══██╗██║     ██║██╔═══╝      ██╔══██║██║
██████╔╝███████╗██║██║          ██║  ██║██║
╚═════╝ ╚══════╝╚═╝╚═╝          ╚═╝  ╚═╝╚═╝
{RESET}
{BOLD}Behavioral Log Investigation Platform — Artificial Intelligence{RESET}
{BLUE}Version 1.0 | Author: Taylor Glass | github.com/tjglass814/BLIP-AI{RESET}
""")

def run_investigation(alert_name, use_claude=True):
    """
    Full investigation pipeline:
    1. Run Splunk queries via investigation engine
    2. Score confidence and determine verdict
    3. Send findings to Claude for reasoning (if available)
    4. Print complete report
    """

    start_time = time.time()

    # Step 1 — Run investigation engine
    engine = InvestigationEngine()
    findings = engine.investigate(alert_name, hours=24)
    engine.print_report()

    # Step 2 — Claude reasoning layer
    if use_claude:
        print(f"\n{BLUE}{BOLD}[CLAUDE ANALYST]{RESET} Sending findings to Claude for reasoning...")

        analyst = ClaudeAnalyst()
        success, test_response = analyst.test_connection()

        if success:
            print(f"{GREEN}✅ Claude connected — analyzing findings...{RESET}\n")
            analysis = analyst.analyze(findings)

            print(f"{BOLD}{'='*60}{RESET}")
            print(f"{BOLD}CLAUDE SOC ANALYST ASSESSMENT{RESET}")
            print(f"{BOLD}{'='*60}{RESET}")
            print(analysis)
            print(f"{BOLD}{'='*60}{RESET}")

            findings["claude_analysis"] = analysis
        else:
            print(f"{YELLOW}⚠️  Claude API not available — investigation complete without reasoning layer.{RESET}")
            print(f"{YELLOW}    Splunk-based findings are still valid and actionable.{RESET}")
            findings["claude_analysis"] = "Claude API unavailable"

    # Step 3 — Save report
    elapsed = round(time.time() - start_time, 2)
    findings["investigation_duration_seconds"] = elapsed

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = alert_name.replace(" ", "_").replace("/", "_")[:50]
    report_path = f"reports/{safe_name}_{timestamp}.json"

    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)

    print(f"\n{GREEN}✅ Report saved: {report_path}{RESET}")
    print(f"{GREEN}✅ Investigation completed in {elapsed} seconds{RESET}")

    # Step 4 — Auto-response check
    confidence = findings.get("confidence_score", 0)
    if confidence >= 0.90:
        print(f"\n{RED}{BOLD}🚨 AUTO-RESPONSE THRESHOLD REACHED (confidence={confidence}){RESET}")
        print(f"{RED}   Actions that would fire in production:{RESET}")
        src_ip = findings.get("src_ip")
        if src_ip:
            print(f"{RED}   → Block {src_ip} at OPNsense firewall{RESET}")
        print(f"{RED}   → Create TheHive case{RESET}")
        print(f"{RED}   → Generate PDF report{RESET}")
        print(f"{YELLOW}   (Auto-response disabled in V1 — manual confirmation required){RESET}")

    return findings


def run_continuous_monitor(interval_minutes=5):
    """
    Continuous monitoring mode.
    Checks for new triggered alerts every N minutes
    and automatically investigates them.
    """
    print(f"{BOLD}Starting continuous monitoring mode...{RESET}")
    print(f"Checking for new alerts every {interval_minutes} minutes.")
    print(f"Press Ctrl+C to stop.\n")

    investigated = set()

    while True:
        try:
            print(f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Checking for new alerts...")

            engine = InvestigationEngine()
            alerts = engine.splunk.get_triggered_alerts(hours=1)

            new_alerts = []
            for alert in alerts:
                name = alert.get("alert_name", "")
                time_str = alert.get("_time", "")
                alert_id = f"{name}_{time_str}"

                if alert_id not in investigated:
                    new_alerts.append(alert)
                    investigated.add(alert_id)

            if new_alerts:
                print(f"{GREEN}Found {len(new_alerts)} new alert(s) — investigating...{RESET}")
                for alert in new_alerts[:3]:
                    name = alert.get("alert_name", "Unknown Alert")
                    run_investigation(name)
            else:
                print(f"No new alerts. Next check in {interval_minutes} minutes.")

            time.sleep(interval_minutes * 60)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Monitoring stopped.{RESET}")
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
            time.sleep(30)


if __name__ == "__main__":
    import sys

    print_banner()

    if len(sys.argv) > 1:
        if sys.argv[1] == "monitor":
            # Continuous monitoring mode
            run_continuous_monitor(interval_minutes=5)
        else:
            # Investigate specific alert passed as argument
            alert_name = " ".join(sys.argv[1:])
            run_investigation(alert_name)
    else:
        # Default — investigate most recent alert
        print(f"{BOLD}Running single investigation on most recent alert...{RESET}\n")
        engine = InvestigationEngine()
        alerts = engine.splunk.get_triggered_alerts(hours=24)

        if alerts:
            most_recent = alerts[0].get("alert_name", "Unknown Alert")
            print(f"Most recent alert: {most_recent}\n")
            run_investigation(most_recent)
        else:
            print(f"{YELLOW}No recent alerts found. Running test investigation...{RESET}\n")
            run_investigation("Privilege Escalation Confirmed (euid=0 Non-Root User)")
