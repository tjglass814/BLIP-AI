"""
BLIP-AI Splunk Connector
========================
Handles all communication with Splunk REST API.
Pulls triggered alerts and runs investigation queries.
"""

import os
import json
import time
import requests
import urllib3
from dotenv import load_dotenv

# Suppress SSL warnings for self-signed Splunk cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv("config/.env")

class SplunkConnector:

    def __init__(self):
        self.host = os.getenv("SPLUNK_HOST")
        self.port = os.getenv("SPLUNK_PORT")
        self.username = os.getenv("SPLUNK_USERNAME")
        self.password = os.getenv("SPLUNK_PASSWORD")
        self.index = os.getenv("SPLUNK_INDEX")
        self.base_url = f"https://{self.host}:{self.port}"
        self.auth = (self.username, self.password)

    def run_query(self, spl_query, earliest="-15m", latest="now"):
        """
        Run a Splunk SPL query and return results as a list of dicts.
        This is the core function everything else calls.
        """
        try:
            # Submit search job
            search_url = f"{self.base_url}/services/search/jobs"
            response = requests.post(
                search_url,
                data={
                    "search": spl_query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                    "exec_mode": "blocking"
                },
                auth=self.auth,
                verify=False,
                timeout=60
            )

            if response.status_code != 201:
                print(f"Search submission failed: {response.status_code}")
                return []

            job_id = response.json().get("sid")

            # Get results
            results_url = f"{self.base_url}/services/search/jobs/{job_id}/results"
            results = requests.get(
                results_url,
                params={"output_mode": "json", "count": 100},
                auth=self.auth,
                verify=False,
                timeout=30
            )

            if results.status_code == 200:
                return results.json().get("results", [])
            else:
                print(f"Results fetch failed: {results.status_code}")
                return []

        except Exception as e:
            print(f"Query error: {e}")
            return []

    def get_triggered_alerts(self, hours=1):
        """
        Get all alerts that fired in the last N hours.
        Returns list of alert names and timestamps.
        """
        query = f"""
            search index=_audit action=alert_fired earliest=-{hours}h
            | rex field=_raw "ss_name=\\"(?P<alert_name>[^\\"]+)\\""
            | table _time alert_name
            | sort -_time
        """
        results = self.run_query(query, earliest=f"-{hours}h")
        return results

    def get_event_count(self, sourcetype, hours=1):
        """Get total event count for a sourcetype."""
        query = f"""
            search index=main sourcetype={sourcetype} earliest=-{hours}h
            | stats count
        """
        results = self.run_query(query, earliest=f"-{hours}h")
        if results:
            return int(results[0].get("count", 0))
        return 0

    def check_ssh_brute_force(self, src_ip=None, hours=1):
        """Detection query from Project 1 — SSH brute force."""
        ip_filter = f'| where src_ip="{src_ip}"' if src_ip else ""
        query = f"""
            search index=main sourcetype=linux_secure "Failed password" earliest=-{hours}h
            | rex field=_raw "Failed password for \\S+ from (?P<src_ip>\\d+.\\d+.\\d+.\\d+)"
            | stats count by src_ip
            | where count > 5
            {ip_filter}
            | sort -count
        """
        return self.run_query(query, earliest=f"-{hours}h")

    def check_port_scan(self, src_ip=None, hours=1):
        """Detection query from Project 5 — network reconnaissance."""
        query = f"""
            search index=main sourcetype=syslog earliest=-{hours}h
            | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+),(?P<dst_ip>[\\d.]+),(?P<src_port>\\d+),(?P<dst_port>\\d+)"
            | where isnotnull(src_ip) AND isnotnull(dst_port)
            | bin _time span=5m
            | stats dc(dst_port) as unique_ports count as total_packets by src_ip dst_ip _time
            | where unique_ports >= 10
            | sort -unique_ports
        """
        results = self.run_query(query, earliest=f"-{hours}h")
        if src_ip:
            results = [r for r in results if r.get("src_ip") == src_ip]
        return results

    def check_privilege_escalation(self, hours=1):
        """Detection query from Project 3 — euid=0 from non-root."""
        query = f"""
            search index=main sourcetype=linux_audit type=SYSCALL earliest=-{hours}h
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "(?i)euid[=:\\"](?P<euid>\\d+)"
            | rex field=_raw "exe=\\"(?P<exe>[^\\"]+)\\""
            | rex field=_raw "success=(?P<success>\\w+)"
            | where euid="0" AND auid!="unset" AND auid!="root" AND auid!="4294967295"
            | where success="yes"
            | eval binary=mvindex(split(exe,"/"),-1)
            | where binary!="cron" AND binary!="sshd" AND binary!="passwd"
            | stats count values(exe) as processes by auid host
            | sort -count
        """
        return self.run_query(query, earliest=f"-{hours}h")

    def check_persistence(self, hours=4):
        """Detection queries from Project 4 — persistence mechanisms."""
        query = f"""
            search index=main sourcetype=linux_audit earliest=-{hours}h
            (key="ssh_key_modification" OR key="cron_modification"
            OR key="systemd_modification" OR key="startup_modification")
            | rex field=_raw "AUID=\\"(?P<auid>[^\\"]+)\\""
            | rex field=_raw "key=\\"(?P<key>[^\\"]+)\\""
            | rex field=_raw "comm=\\"(?P<comm>[^\\"]+)\\""
            | where auid!="unset" AND auid!="4294967295"
            | stats count values(key) as mechanisms values(comm) as tools by auid host
            | sort -count
        """
        return self.run_query(query, earliest=f"-{hours}h")

    def check_recon_campaign(self, hours=4):
        """Detection query from Project 5 — repeated scanning."""
        query = f"""
            search index=main sourcetype=syslog earliest=-{hours}h
            | rex field=_raw "(?P<src_ip>10\\.10\\.10\\.\\d+),(?P<dst_ip>[\\d.]+),(?P<src_port>\\d+),(?P<dst_port>\\d+)"
            | where isnotnull(src_ip) AND isnotnull(dst_port)
            | bin _time span=5m
            | stats dc(dst_port) as unique_ports by src_ip dst_ip _time
            | where unique_ports >= 10
            | stats count as scan_windows avg(unique_ports) as avg_ports by src_ip
            | where scan_windows >= 2
            | eval campaign_summary=src_ip." scanned ".tostring(round(avg_ports,0))." avg ports across ".tostring(scan_windows)." windows"
            | sort -scan_windows
        """
        return self.run_query(query, earliest=f"-{hours}h")


if __name__ == "__main__":
    print("Testing Splunk Connector...")
    splunk = SplunkConnector()

    print("\n1. Checking triggered alerts (last hour)...")
    alerts = splunk.get_triggered_alerts(hours=24)
    if alerts:
        print(f"   Found {len(alerts)} alert fires:")
        for a in alerts[:5]:
            print(f"   - {a.get('alert_name')} at {a.get('_time')}")
    else:
        print("   No alerts in last 24 hours")

    print("\n2. Checking for privilege escalation...")
    escalation = splunk.check_privilege_escalation(hours=24)
    if escalation:
        print(f"   Found {len(escalation)} escalation events")
        for e in escalation[:3]:
            print(f"   - AUID: {e.get('auid')} Processes: {e.get('processes')}")
    else:
        print("   No escalation events found")

    print("\n3. Checking for persistence mechanisms...")
    persistence = splunk.check_persistence(hours=24)
    if persistence:
        print(f"   Found {len(persistence)} persistence events")
        for p in persistence[:3]:
            print(f"   - AUID: {p.get('auid')} Mechanisms: {p.get('mechanisms')}")
    else:
        print("   No persistence events found")

    print("\n4. Checking for network reconnaissance...")
    recon = splunk.check_recon_campaign(hours=24)
    if recon:
        print(f"   Found {len(recon)} recon campaigns")
        for r in recon[:3]:
            print(f"   - {r.get('campaign_summary')}")
    else:
        print("   No recon campaigns found")

    print("\n✅ Splunk connector test complete")
