#!/usr/bin/env python3
"""
QRadar Rule Deploy Script
=========================
Reads detection rules from JSON files and executes their AQL queries against
QRadar via the Ariel Search REST API. Suspicious matches are reported in the
GitHub Actions log as alerts.

Workflow:
    GitHub push -> Actions trigger -> deploy.py -> QRadar /api/ariel/searches
                                                -> Print matched events

JSON Schema Expected (matches qradar/rules/*.json):
    {
      "name": "Rule name",
      "description": "...",
      "severity": <int 1-10>,
      "credibility": <int 1-10>,
      "category": "...",
      "mitre": {
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "technique": "T1110.001",
        "technique_name": "..."
      },
      "detection": {
        "aql": "SELECT ... FROM events WHERE ...",
        "threshold": <int>,
        "time_window_seconds": <int>
      },
      "response": {
        "offense_name": "...",
        "offense_description": "..."
      },
      "tags": ["tag1", "tag2"]
    }
"""

import os
import re
import json
import requests
import glob
import sys
import time
import urllib3
from datetime import datetime, timedelta

os.environ['GIT_CONFIG_NOSYSTEM'] = '1'
os.environ['GIT_CONFIG_GLOBAL'] = '/tmp/.gitconfig'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST  = os.environ.get('QRADAR_HOST', '').rstrip('/')
QRADAR_TOKEN = os.environ.get('QRADAR_SEC_TOKEN', '')

if not QRADAR_HOST or not QRADAR_TOKEN:
    print("ERROR: QRADAR_HOST or QRADAR_SEC_TOKEN environment variables not set!")
    print("       Configure them in GitHub repo Settings -> Secrets and variables -> Actions")
    sys.exit(1)

if not QRADAR_HOST.startswith('http'):
    QRADAR_HOST = f'https://{QRADAR_HOST}'

HEADERS = {
    'SEC'     : QRADAR_TOKEN,
    'Accept'  : 'application/json',
    'Version' : '17.0'
}

RULES_GLOB = 'qradar/rules/*.json'

SEVERITY_MAP = {
    range(1, 4):  'LOW',
    range(4, 7):  'MEDIUM',
    range(7, 9):  'HIGH',
    range(9, 11): 'CRITICAL'
}


def severity_to_label(sev_int):
    """Convert numeric severity (1-10) to human label."""
    try:
        sev = int(sev_int)
    except (TypeError, ValueError):
        return str(sev_int)
    for r, label in SEVERITY_MAP.items():
        if sev in r:
            return label
    return 'UNKNOWN'


def build_aql(aql_template):
    """Clean AQL: strip QRadar-incompatible bits, fix payload references,
    inject START/STOP time window for the last 1 hour."""

    aql = aql_template.strip()

    aql = re.sub(r'ORDER\s+BY\s+\S+(\s+(ASC|DESC))?', '', aql, flags=re.IGNORECASE)
    aql = re.sub(r'LAST\s+\d+\s+(SECONDS|MINUTES|HOURS|DAYS)', '', aql, flags=re.IGNORECASE)

    select_part = re.search(r'SELECT(.+?)FROM', aql, re.DOTALL | re.IGNORECASE)
    if select_part:
        select_fixed = re.sub(
            r'(?<!UTF8\()\bpayload\b',
            'UTF8(payload)',
            select_part.group(1)
        )
        aql = aql[:select_part.start(1)] + select_fixed + aql[select_part.end(1):]

    where_part = re.search(r'WHERE(.+?)$', aql, re.DOTALL | re.IGNORECASE)
    if where_part:
        where_fixed = re.sub(
            r'(?<!UTF8\()\bpayload\b',
            'UTF8(payload)',
            where_part.group(1)
        )
        aql = aql[:where_part.start(1)] + where_fixed

    aql = aql.strip().rstrip(';').strip()

    now   = datetime.utcnow()
    start = now - timedelta(hours=1)

    aql_final = (
        f"{aql} "
        f"START '{start.strftime('%Y-%m-%d %H:%M')}' "
        f"STOP '{now.strftime('%Y-%m-%d %H:%M')}'"
    )

    return aql_final


def run_aql_search(aql_template):
    """Submit AQL search to QRadar, poll for completion, return events."""
    aql = build_aql(aql_template)

    print(f"   Submitting AQL query to QRadar...")
    print(f"   Preview: {aql[:140]}...")

    headers_post = {
        **HEADERS,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        r = requests.post(
            f'{QRADAR_HOST}/api/ariel/searches',
            headers=headers_post,
            data=f'query_expression={requests.utils.quote(aql)}',
            verify=False,
            timeout=30
        )
    except requests.exceptions.RequestException as e:
        print(f"   ERROR: Could not reach QRadar - {e}")
        return None

    if r.status_code not in [200, 201]:
        print(f"   ERROR: HTTP {r.status_code}")
        print(f"   Response: {r.text[:300]}")
        return None

    search_id = r.json().get('search_id')
    print(f"   Search ID: {search_id}")

    for i in range(20):
        time.sleep(3)
        try:
            sr = requests.get(
                f'{QRADAR_HOST}/api/ariel/searches/{search_id}',
                headers=HEADERS,
                verify=False,
                timeout=30
            )
            status = sr.json().get('status')
            print(f"   Poll [{i+1}/20]: {status}")
            if status == 'COMPLETED':
                break
            elif status == 'ERROR':
                print("   ERROR: AQL execution failed on QRadar side")
                return None
        except requests.exceptions.RequestException as e:
            print(f"   ERROR during polling: {e}")
            return None
    else:
        print("   WARNING: Search did not complete within timeout window")
        return None

    try:
        rr = requests.get(
            f'{QRADAR_HOST}/api/ariel/searches/{search_id}/results',
            headers=HEADERS,
            verify=False,
            timeout=60
        )
    except requests.exceptions.RequestException as e:
        print(f"   ERROR fetching results: {e}")
        return None

    if rr.status_code == 200:
        events = rr.json().get('events', [])
        print(f"   Retrieved {len(events)} event(s)")
        return events

    print(f"   ERROR: Could not fetch results, HTTP {rr.status_code}")
    return None


def process_rule(rule_data, file_path):
    """Parse a rule JSON (our schema) and execute its AQL search."""

    name        = rule_data.get('name', 'Unnamed Rule')
    description = rule_data.get('description', '')
    severity    = rule_data.get('severity', 'N/A')
    credibility = rule_data.get('credibility', 'N/A')
    category    = rule_data.get('category', 'N/A')
    enabled     = rule_data.get('enabled', True)

    mitre   = rule_data.get('mitre', {})
    tactic  = f"{mitre.get('tactic', '')} - {mitre.get('tactic_name', '')}".strip(' -')
    techniq = f"{mitre.get('technique', '')} - {mitre.get('technique_name', '')}".strip(' -')

    detection = rule_data.get('detection', {})
    aql       = detection.get('aql', '')
    threshold = detection.get('threshold', detection.get('threshold_connections', 'N/A'))
    window    = detection.get('time_window_seconds', 'N/A')

    response_cfg = rule_data.get('response', {})
    offense_name = response_cfg.get('offense_name', name)

    tags = rule_data.get('tags', [])

    print(f"\n{'='*60}")
    print(f"  Rule       : {name}")
    print(f"  File       : {file_path}")
    print(f"  Severity   : {severity} ({severity_to_label(severity)})")
    print(f"  Credibility: {credibility}/10")
    print(f"  Category   : {category}")
    print(f"  Tactic     : {tactic}")
    print(f"  Technique  : {techniq}")
    print(f"  Threshold  : {threshold} within {window}s")
    print(f"  Tags       : {', '.join(tags) if tags else 'none'}")
    print(f"  Enabled    : {enabled}")
    print(f"{'='*60}")

    if not enabled:
        print("   SKIPPED: Rule is disabled (enabled=false)")
        return True

    if not aql:
        print("   ERROR: No AQL query found in detection.aql field!")
        return False

    events = run_aql_search(aql)

    if events is None:
        return False

    if len(events) > 0:
        print(f"\n   *** ALERT: {len(events)} suspicious event(s) detected! ***")
        print(f"   Offense  : {offense_name}")
        for i, ev in enumerate(events[:5]):
            print(f"\n   [Event {i+1}]")
            for key in ('EventName', 'sourceIP', 'destinationIP', 'username',
                        'destinationPort', 'LogSource', 'DomainName'):
                val = ev.get(key)
                if val not in (None, '', 'N/A'):
                    print(f"     {key:<16}: {val}")
        if len(events) > 5:
            print(f"\n   ... and {len(events)-5} more event(s)")
    else:
        print("\n   OK: No suspicious events matched this rule")

    return True


def main():
    if not os.path.exists('/tmp/.gitconfig'):
        with open('/tmp/.gitconfig', 'w') as f:
            f.write('[user]\n\tname = QRadarDeploy\n\temail = deploy@local\n')

    print("=" * 60)
    print("  QRadar Detection Rule Deployment — GitHub Actions CI")
    print("=" * 60)
    print(f"  Host       : {QRADAR_HOST}")
    print(f"  Time (UTC) : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Rule glob  : {RULES_GLOB}")
    print("=" * 60)

    rule_files = sorted(glob.glob(RULES_GLOB))

    if not rule_files:
        print(f"\nERROR: No JSON files found at {RULES_GLOB}")
        print("       Make sure rules live under qradar/rules/")
        sys.exit(1)

    print(f"\nFound {len(rule_files)} rule file(s) to process.")

    ok = fail = skipped = 0
    alerted_rules = []

    for f in rule_files:
        print(f"\n>>> Processing: {f}")
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            if not data:
                print("   ERROR: Empty JSON file")
                fail += 1
                continue

            result = process_rule(data, f)
            if result:
                ok += 1
            else:
                fail += 1

        except json.JSONDecodeError as e:
            print(f"   ERROR: Invalid JSON syntax — {e}")
            fail += 1
        except Exception as e:
            print(f"   ERROR: Unexpected exception — {e}")
            fail += 1

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT SUMMARY")
    print(f"{'='*60}")
    print(f"  Total rules    : {len(rule_files)}")
    print(f"  Successful     : {ok}")
    print(f"  Failed         : {fail}")
    print(f"  Skipped (disabled): {skipped}")
    print(f"{'='*60}")

    sys.exit(0 if fail == 0 else 1)


if __name__ == '__main__':
    main()
