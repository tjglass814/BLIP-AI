"""
BLIP-AI Connection Test
Verifies Splunk and Anthropic API connectivity before building the investigation engine.
"""

import os
import sys
from dotenv import load_dotenv

# Load credentials from config/.env
load_dotenv("config/.env")

def test_anthropic():
    print("\n--- Testing Anthropic API Connection ---")
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=100,
            messages=[
                {
                    "role": "user",
                    "content": "Respond with exactly this text: BLIP-AI Anthropic connection successful."
                }
            ]
        )
        print(f"✅ {message.content[0].text}")
        return True
    except Exception as e:
        print(f"❌ Anthropic connection failed: {e}")
        return False

def test_splunk():
    print("\n--- Testing Splunk API Connection ---")
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        host = os.getenv("SPLUNK_HOST")
        port = os.getenv("SPLUNK_PORT")
        username = os.getenv("SPLUNK_USERNAME")
        password = os.getenv("SPLUNK_PASSWORD")

        # Authenticate with Splunk REST API
        auth_url = f"https://{host}:{port}/services/auth/login"
        response = requests.post(
            auth_url,
            data={"username": username, "password": password},
            verify=False
        )

        if response.status_code == 200:
            print(f"✅ Splunk connection successful — authenticated as {username}")
            print(f"   Host: {host}:{port}")
            return True
        else:
            print(f"❌ Splunk authentication failed — status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"❌ Splunk connection failed: {e}")
        return False

def test_splunk_query():
    print("\n--- Testing Splunk Search API ---")
    try:
        import requests
        import urllib3
        import time
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        host = os.getenv("SPLUNK_HOST")
        port = os.getenv("SPLUNK_PORT")
        username = os.getenv("SPLUNK_USERNAME")
        password = os.getenv("SPLUNK_PASSWORD")

        # Run a simple test search
        search_url = f"https://{host}:{port}/services/search/jobs"
        search_query = "search index=main | head 1 | stats count"

        response = requests.post(
            search_url,
            data={
                "search": search_query,
                "output_mode": "json",
                "exec_mode": "blocking"
            },
            auth=(username, password),
            verify=False
        )

        if response.status_code == 201:
            result = response.json()
            job_id = result.get("sid")
            print(f"✅ Splunk search API working — Job ID: {job_id}")

            # Get results
            results_url = f"https://{host}:{port}/services/search/jobs/{job_id}/results"
            results = requests.get(
                results_url,
                params={"output_mode": "json"},
                auth=(username, password),
                verify=False
            )

            if results.status_code == 200:
                data = results.json()
                count = data.get("results", [{}])[0].get("count", "unknown")
                print(f"✅ Splunk query returned results — event count: {count}")
                return True
        else:
            print(f"❌ Splunk search failed — status {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Splunk search test failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("BLIP-AI Connection Tests")
    print("=" * 50)

    anthropic_ok = test_anthropic()
    splunk_ok = test_splunk()
    query_ok = test_splunk_query()

    print("\n" + "=" * 50)
    print("Results:")
    print(f"  Anthropic API:  {'✅ Connected' if anthropic_ok else '❌ Failed'}")
    print(f"  Splunk Auth:    {'✅ Connected' if splunk_ok else '❌ Failed'}")
    print(f"  Splunk Search:  {'✅ Connected' if query_ok else '❌ Failed'}")
    print("=" * 50)

    if anthropic_ok and splunk_ok and query_ok:
        print("\n🟢 All systems go. BLIP-AI is ready to build.")
    else:
        print("\n🔴 Fix connection issues before proceeding.")
        sys.exit(1)
