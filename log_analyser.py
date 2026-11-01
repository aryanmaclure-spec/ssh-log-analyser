#!/usr/bin/env python3
"""
SSH Log Analyser
----------------
Reads a Linux SSH authentication log (like /var/log/auth.log) and flags
suspicious activity a SOC analyst would care about:

  1. Brute-force attempts   - one IP failing to log in many times in a
                              short burst (default: 5+ fails within 60s)
  2. Username enumeration   - one IP trying lots of different usernames
  3. Invalid users          - logins for accounts that don't exist
  4. Possible compromise    - an IP that failed a lot, THEN succeeded

Usage:
    python3 log_analyser.py sample_auth.log
    python3 log_analyser.py sample_auth.log --threshold 3
    python3 log_analyser.py sample_auth.log --window 300
    python3 log_analyser.py sample_auth.log --csv report.csv
"""

import argparse          # reads command-line options like --threshold
import csv               # writes the optional CSV report
import re                # regular expressions: pattern matching on log lines
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# 1. REGEX PATTERNS
# Each SSH log line follows a predictable format. A regex lets us pull out
# just the parts we need (the username and IP address).
#
# Example line:
#   Nov  1 03:14:07 server sshd[2211]: Failed password for root from 45.83.12.9 port 51234 ssh2
#
#   (?P<user>\S+)  -> capture a group called "user": one or more non-space chars
#   (?P<ip>[\d.]+) -> capture a group called "ip": digits and dots
# ---------------------------------------------------------------------------
TIMESTAMP = r"^(?P<time>\w{3}\s+\d+\s[\d:]{8})"

FAILED = re.compile(
    TIMESTAMP + r".*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED = re.compile(
    TIMESTAMP + r".*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
INVALID = re.compile(
    TIMESTAMP + r".*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)


def parse_time(stamp):
    """Turn a syslog timestamp like 'Nov  1 03:14:07' into a datetime.

    Syslog lines don't include the year, so we add a placeholder one.
    2000 is a leap year, so 'Feb 29' still parses.
    """
    return datetime.strptime(f"2000 {stamp}", "%Y %b %d %H:%M:%S")


def max_fails_in_window(times, window):
    """Find the busiest burst of failures for one IP.

    Uses a "sliding window": two pointers walk through the sorted times.
    'end' moves forward one failure at a time; 'start' catches up whenever
    the gap between them is bigger than the window. The number of failures
    between the two pointers is how many happened inside that window.

    Returns (most failures inside any window, time that burst started).
    """
    times = sorted(times)
    best_count, best_start = 0, None
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        count = end - start + 1
        if count > best_count:
            best_count, best_start = count, times[start]
    return best_count, best_start


def parse_log(path):
    """Read the log file line by line and sort each event into a bucket."""
    failed = []      # list of (time, user, ip)
    accepted = []
    invalid = []

    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                # Check the most specific patterns first.
                if m := FAILED.search(line):
                    failed.append((m["time"], m["user"], m["ip"]))
                elif m := ACCEPTED.search(line):
                    accepted.append((m["time"], m["user"], m["ip"]))
                elif m := INVALID.search(line):
                    invalid.append((m["time"], m["user"], m["ip"]))
    except FileNotFoundError:
        sys.exit(f"Error: can't find '{path}'")

    return failed, accepted, invalid


def analyse(failed, accepted, invalid, threshold, window_seconds):
    """Turn raw events into findings."""
    findings = []
    window = timedelta(seconds=window_seconds)

    # How many failures did each IP rack up across the whole log?
    # (Used for the "top IPs" table, not for the brute-force rule.)
    fails_per_ip = Counter(ip for _, _, ip in failed)

    # When did each IP fail? Needed for the time-window check.
    fail_times_per_ip = defaultdict(list)
    for time, _, ip in failed:
        fail_times_per_ip[ip].append(parse_time(time))

    # Which usernames did each IP try? (a set ignores duplicates)
    users_per_ip = defaultdict(set)
    for _, user, ip in failed + invalid:
        users_per_ip[ip].add(user)

    # --- Rule 1: brute force -------------------------------------------
    # Only flag an IP if it fails 'threshold' times within the time window.
    # A burst like that is a script hammering the server. The same number
    # of fails spread over a day is usually just people mistyping.
    brute_force = {}   # ip -> time its busiest burst started
    for ip, times in fail_times_per_ip.items():
        burst, burst_start = max_fails_in_window(times, window)
        if burst >= threshold:
            brute_force[ip] = burst_start
            findings.append({
                "severity": "HIGH",
                "type": "Brute force",
                "ip": ip,
                "detail": f"{burst} failed logins within {window_seconds}s "
                          f"({fails_per_ip[ip]} total)",
            })

    # --- Rule 2: username enumeration -----------------------------------
    # Trying 5+ different usernames suggests the attacker is guessing
    # which accounts exist, not just guessing one password.
    for ip, users in users_per_ip.items():
        if len(users) >= 5:
            findings.append({
                "severity": "MEDIUM",
                "type": "Username enumeration",
                "ip": ip,
                "detail": f"{len(users)} usernames tried: {', '.join(sorted(users)[:6])}...",
            })

    # --- Rule 3: possible compromise ------------------------------------
    # An IP that was flagged for brute force AND got in after the burst
    # started is the scariest finding: the attacker may have guessed the password.
    for time, user, ip in accepted:
        if ip in brute_force and parse_time(time) >= brute_force[ip]:
            findings.append({
                "severity": "CRITICAL",
                "type": "Login after brute force",
                "ip": ip,
                "detail": f"'{user}' logged in at {time} after {fails_per_ip[ip]} failures",
            })

    # Sort so CRITICAL shows first.
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return findings, fails_per_ip


def print_report(failed, accepted, invalid, findings, fails_per_ip):
    print("=" * 62)
    print(" SSH LOG ANALYSIS REPORT")
    print("=" * 62)
    print(f" Failed logins:      {len(failed)}")
    print(f" Successful logins:  {len(accepted)}")
    print(f" Invalid-user hits:  {len(invalid)}")
    print(f" IPs with failures:  {len(fails_per_ip)}")

    print("\n TOP 5 IPs BY FAILED LOGINS")
    for ip, count in fails_per_ip.most_common(5):
        bar = "#" * min(count, 40)
        print(f"   {ip:<16} {count:>4}  {bar}")

    print("\n FINDINGS")
    if not findings:
        print("   Nothing suspicious found.")
    for f in findings:
        print(f"   [{f['severity']:<8}] {f['type']:<24} {f['ip']:<16} {f['detail']}")
    print("=" * 62)


def save_csv(findings, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "type", "ip", "detail"])
        writer.writeheader()
        writer.writerows(findings)
    print(f"\n Saved findings to {path}")


def main():
    parser = argparse.ArgumentParser(description="Detect attacks in SSH auth logs")
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed logins within the window before an IP counts as brute force (default 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="time window in seconds for the brute-force rule (default 60)")
    parser.add_argument("--csv", help="also save findings to this CSV file")
    args = parser.parse_args()

    failed, accepted, invalid = parse_log(args.logfile)
    findings, fails_per_ip = analyse(failed, accepted, invalid, args.threshold, args.window)
    print_report(failed, accepted, invalid, findings, fails_per_ip)

    if args.csv:
        save_csv(findings, args.csv)


if __name__ == "__main__":
    main()
