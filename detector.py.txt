#!/usr/bin/env python3
"""SSH Brute-Force Detector: analyzes Linux auth logs for suspicious login activity."""
import argparse, json, re
from collections import defaultdict
from datetime import datetime, timedelta

FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
SUCCESS = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd.*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")


def parse_ts(raw, year):
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def analyze(path, threshold, window_s, year):
    fails = defaultdict(list)      # ip -> [(time, user)]
    successes = defaultdict(list)  # ip -> [(time, user)]
    with open(path, errors="ignore") as f:
        for line in f:
            if m := FAILED.match(line):
                fails[m["ip"]].append((parse_ts(m["ts"], year), m["user"]))
            elif m := SUCCESS.match(line):
                successes[m["ip"]].append((parse_ts(m["ts"], year), m["user"]))

    window = timedelta(seconds=window_s)
    findings = []
    for ip, events in fails.items():
        events.sort()
        times = [t for t, _ in events]
        burst, start = 0, 0
        for end in range(len(times)):          # sliding window
            while times[end] - times[start] > window:
                start += 1
            burst = max(burst, end - start + 1)
        if burst >= threshold:
            compromised = [u for t, u in successes.get(ip, []) if t >= times[0]]
            findings.append({
                "ip": ip,
                "total_failures": len(events),
                "max_failures_in_window": burst,
                "users_targeted": sorted({u for _, u in events}),
                "first_seen": str(times[0]),
                "last_seen": str(times[-1]),
                "success_after_failures": bool(compromised),
                "severity": "CRITICAL" if compromised else "HIGH",
            })
    return sorted(findings, key=lambda x: -x["total_failures"])


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs")
    p.add_argument("logfile")
    p.add_argument("-t", "--threshold", type=int, default=5, help="failures within window to flag")
    p.add_argument("-w", "--window", type=int, default=60, help="window in seconds")
    p.add_argument("-y", "--year", type=int, default=datetime.now().year)
    p.add_argument("-o", "--output", help="save findings as JSON")
    a = p.parse_args()

    results = analyze(a.logfile, a.threshold, a.window, a.year)
    if not results:
        print("No suspicious activity found.")
    for r in results:
        print(f"[{r['severity']}] {r['ip']}  failures={r['total_failures']} "
              f"(peak {r['max_failures_in_window']}/{a.window}s)  users={','.join(r['users_targeted'])}")
        if r["success_after_failures"]:
            print("    !! Successful login after failed attempts: investigate this host/account")
        print(f"    block with: sudo ufw deny from {r['ip']}")
    if a.output:
        with open(a.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved report to {a.output}")


if __name__ == "__main__":
    main()
