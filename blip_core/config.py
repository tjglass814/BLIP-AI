"""
BLIP-AI Core — Configuration
============================
Shared settings for the investigation core. Splunk and Claude
credentials are loaded exactly as in the V1.1 engine (config/.env via
python-dotenv, inside splunk_connector.py / claude_analyst.py) — this
module does not duplicate that. It only holds the guardrail limits and
loop settings specific to the governed agent.
"""

MAX_ITERATIONS = 5
MAX_QUERY_HOURS = 24
