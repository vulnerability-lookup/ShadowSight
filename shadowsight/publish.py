import argparse
import json
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from shadowsight.shadow import api_call
from shadowsight.utils import (
    extract_vulnerability_ids,
    push_sighting_to_vulnerability_lookup,
)


def honeypot_exploited_vulnerabilities(day, limit):
    """Lists the honeypot exploited vulnerabilities in descending order of number of IPs for a given day."""
    formatted_day = day.strftime("%Y-%m-%d")
    if limit:
        query = {"date": f"{formatted_day}", "limit": f"{limit}"}
    else:
        query = {"date": f"{formatted_day}"}

    # Query the Shadowserver API
    response = api_call("honeypot/exploited-vulnerabilities", query)

    # Decode the bytes to a string and split by newline
    try:
        lines = response.decode("utf-8").strip().split("\n")
    except Exception:
        return

    # Convert each JSON object to a Python dictionary
    try:
        json_objects = [json.loads(line) for line in lines]
    except Exception:
        return

    for elem in json_objects:
        if vuln := elem.get("vulnerability", ""):
            vulnerability_ids = extract_vulnerability_ids(vuln)
            if vulnerability_ids:
                push_sighting_to_vulnerability_lookup(
                    "exploited",
                    f"The Shadowserver (honeypot/exploited-vulnerabilities) - ({formatted_day})",
                    day,
                    vulnerability_ids,
                )


def honeypot_common_vulnerabilities(day, limit):
    "Honeypot CVE statistics."
    formatted_day = day.strftime("%Y-%m-%d")
    if limit:
        query = {"date": f"{formatted_day}", "limit": f"{limit}"}
    else:
        query = {"date": f"{formatted_day}"}

    # Query the Shadowserver API
    response = api_call("honeypot/common-vulnerabilities", query)

    # Decode the bytes to a string and split by newline
    try:
        lines = response.decode("utf-8").strip().split("\n")
    except Exception:
        return

    # Convert each JSON object to a Python dictionary
    try:
        json_objects = [json.loads(line) for line in lines]
    except Exception:
        return

    for elem in json_objects:
        if vuln := elem.get("vulnerability", ""):
            vulnerability_ids = extract_vulnerability_ids(vuln)
            if vulnerability_ids:
                push_sighting_to_vulnerability_lookup(
                    "seen",
                    f"The Shadowserver (honeypot/common-vulnerabilities) - ({formatted_day})",
                    day,
                    vulnerability_ids,
                )


def main():
    parser = argparse.ArgumentParser(
        prog="ShadowSight",
        description="ShadowSight Query Script",
    )
    parser.add_argument(
        "--method",
        type=str,
        default="exploited",
        choices=["exploited", "common"],
        help="The set of vulnerabilities (honeypot/exploited-vulnerabilities or honeypot/common-vulnerabilities) from the honeypot group.",
    )
    parser.add_argument(
        "--since",
        type=str,
        default="1d",
        help="Query for exploited vulnerabilities from Shadow Server (back until) this date inclusive (yyyy-mm-dd), or specify an integer to represent days in the past.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of results.",
    )
    args = parser.parse_args()

    today = datetime.now(tz=ZoneInfo("UTC")).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    since_date = None

    try:
        # Check if `--since` is an integer (days in the past)
        since = args.since.replace("d", "")
        if since.isdigit():
            since_date = today - timedelta(days=int(since))
        else:
            since_date = datetime.strptime(args.since, "%Y-%m-%d").replace(
                tzinfo=ZoneInfo("UTC")
            )
        since_date = since_date.replace(hour=0, minute=0, second=0, microsecond=0)
    except ValueError:
        print(
            "Invalid format for --since. Use yyyy-mm-dd or an integer for days in the past."
        )
        sys.exit(1)

    # Main loop to query data
    while since_date <= today:
        print(f"Querying for {since_date.strftime('%Y-%m-%d')}…")

        # Perform the API query or any other operation here
        if args.method == "exploited":
            honeypot_exploited_vulnerabilities(since_date, args.limit)
        elif args.method == "common":
            honeypot_common_vulnerabilities(since_date, args.limit)

        # Increment since_date by one day
        since_date += timedelta(days=1)


if __name__ == "__main__":
    # Point of entry in execution mode
    main()
