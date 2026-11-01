#!/usr/bin/env python3
"""
Generates a realistic fake SSH auth log so you can test the analyser
without needing a real server. All IPs are from documentation/test ranges
or random, and nothing here touches a real system.

Usage:
    python3 generate_sample_log.py            # writes sample_auth.log
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # same "random" log every time, so results are repeatable

start = datetime(2026, 11, 1, 0, 0, 0)
lines = []
pid = 2000


def stamp(t):
    # Syslog format: "Nov  1 03:14:07" (day padded to 2 chars with a space)
    return t.strftime("%b ") + f"{t.day:>2}" + t.strftime(" %H:%M:%S")


def add(t, msg):
    global pid
    pid += 1
    lines.append((t, f"{stamp(t)} webserver sshd[{pid}]: {msg}"))


# Normal staff logins scattered through the day
for _ in range(12):
    t = start + timedelta(minutes=random.randint(0, 1400))
    user = random.choice(["aryan", "admin", "deploy"])
    ip = random.choice(["10.0.0.15", "10.0.0.22", "192.168.1.40"])
    add(t, f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# A couple of genuine typos by staff (should NOT be flagged)
for _ in range(2):
    t = start + timedelta(minutes=random.randint(0, 1400))
    add(t, f"Failed password for aryan from 10.0.0.15 port {random.randint(40000, 60000)} ssh2")

# Attacker 1: classic brute force on root
t = start + timedelta(hours=2)
for _ in range(40):
    t += timedelta(seconds=random.randint(1, 4))
    add(t, f"Failed password for root from 185.220.101.7 port {random.randint(40000, 60000)} ssh2")

# Attacker 2: username enumeration (tries lots of account names)
t = start + timedelta(hours=5)
for user in ["test", "oracle", "postgres", "ubuntu", "git", "ftpuser", "pi", "guest"]:
    t += timedelta(seconds=random.randint(2, 6))
    add(t, f"Invalid user {user} from 103.99.0.122 port {random.randint(40000, 60000)}")
    add(t, f"Failed password for invalid user {user} from 103.99.0.122 port {random.randint(40000, 60000)} ssh2")

# Attacker 3: brute force that SUCCEEDS (the critical one)
t = start + timedelta(hours=9)
for _ in range(15):
    t += timedelta(seconds=random.randint(1, 3))
    add(t, f"Failed password for admin from 45.83.12.9 port {random.randint(40000, 60000)} ssh2")
t += timedelta(seconds=2)
add(t, f"Accepted password for admin from 45.83.12.9 port {random.randint(40000, 60000)} ssh2")

# Background noise: a few one-off scanners
for _ in range(6):
    t = start + timedelta(minutes=random.randint(0, 1400))
    ip = f"{random.randint(20, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    add(t, f"Failed password for root from {ip} port {random.randint(40000, 60000)} ssh2")

# Shared office IP: different staff mistyping their password across the day.
# 6 failures in total, but hours apart, so this is NOT a brute force.
# (Counting across the whole log would wrongly flag it; a time window won't.)
t = start + timedelta(hours=8)
for _ in range(6):
    t += timedelta(minutes=random.randint(60, 120))
    user = random.choice(["aryan", "deploy"])
    add(t, f"Failed password for {user} from 10.0.0.22 port {random.randint(40000, 60000)} ssh2")

lines.sort()
with open("sample_auth.log", "w") as f:
    f.write("\n".join(line for _, line in lines) + "\n")

print(f"Wrote {len(lines)} log lines to sample_auth.log")
