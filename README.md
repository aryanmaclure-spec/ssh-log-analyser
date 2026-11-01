# SSH Log Analyser

A Python tool that reads Linux SSH authentication logs and flags attacks the way a SOC analyst would: brute-force attempts, username enumeration, and, most importantly, successful logins that follow a brute-force attack.

## Why I built it

SSH is one of the most attacked services on the internet. Any server with port 22 open gets thousands of automated login attempts a day. Reading `/var/log/auth.log` by hand doesn't scale, so I wanted a tool that turns a raw log into a short, prioritised list of findings.

## What it detects

| Severity | Finding | Rule |
|---|---|---|
| CRITICAL | Login after brute force | An IP gets flagged for brute force, then logs in successfully |
| HIGH | Brute force | One IP has ≥ 5 failed logins within 60 seconds (both configurable) |
| MEDIUM | Username enumeration | One IP tries ≥ 5 different usernames |

## How to run it

Needs Python 3.8+ and no extra libraries.

```bash
# 1. Make a realistic test log (no real server needed)
python3 generate_sample_log.py

# 2. Analyse it
python3 log_analyser.py sample_auth.log

# Optional: stricter threshold, and export findings to CSV
python3 log_analyser.py sample_auth.log --threshold 3 --csv findings.csv

# Optional: widen the brute-force window to 5 minutes
python3 log_analyser.py sample_auth.log --window 300
```

On a real Linux box you can point it at the system log:

```bash
sudo python3 log_analyser.py /var/log/auth.log
```

## Example output

```
 FINDINGS
   [CRITICAL] Login after brute force  45.83.12.9     'admin' logged in at Nov  1 09:00:31 after 15 failures
   [HIGH    ] Brute force              185.220.101.7  24 failed logins within 60s (40 total)
   [MEDIUM  ] Username enumeration     103.99.0.122   8 usernames tried: ftpuser, git, guest...
```

## How it works

1. **Parsing:** regular expressions pull the timestamp, username and IP out of each `Failed password`, `Accepted` and `Invalid user` line.
2. **Counting:** `Counter` tallies failures per IP; a `defaultdict(set)` tracks which usernames each IP tried.
3. **Time window:** each IP's failure times are sorted, then a sliding window (two pointers) finds the most failures that fall inside any 60-second span.
4. **Rules:** threshold rules turn the counts into findings, sorted by severity.

### Why a time window?

Counting failures across the whole log flags anything that adds up over a day. The sample log includes a shared office IP (`10.0.0.22`) where staff mistype their password 6 times, hours apart. A whole-log count calls that brute force. A 60-second window doesn't, because a real attack script fires dozens of guesses in seconds.

## Limitations and next steps

- A "low and slow" attacker who spaces out guesses (e.g. one every few minutes) won't trip a 60-second window. Running again with a larger `--window` helps catch these.
- Syslog timestamps have no year, so a log spanning New Year's Eve can mis-order events
- Only understands OpenSSH's standard log format
- Ideas: IP geolocation, auto-generating firewall block rules, a simple dashboard

## Skills demonstrated

Python · regex · sliding-window algorithm · log analysis · threat detection · Linux authentication logs · CSV reporting
