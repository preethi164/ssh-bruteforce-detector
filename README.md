# SSH Brute-Force Detector

A lightweight Python tool that analyzes Linux SSH auth logs (`/var/log/auth.log`) and detects brute-force attacks using a sliding-window algorithm.

## Features

* Detects IPs with N failed logins within a time window (configurable)
* Flags **CRITICAL** when a successful login follows failed attempts (possible compromise)
* Lists usernames targeted by each attacker
* Suggests a firewall block command
* Exports findings to JSON
* Zero dependencies (Python 3.8+)

## Usage

```bash
python3 detector.py sample\_auth.log --year 2026
python3 detector.py /var/log/auth.log -t 5 -w 60 -o report.json
```

|Flag|Meaning|Default|
|-|-|-|
|`-t`|Failures needed to flag an IP|5|
|`-w`|Window size in seconds|60|
|`-y`|Log year (syslog has none)|current|
|`-o`|JSON output file|none|

## Sample output

```
\[CRITICAL] 203.0.113.45  failures=12 (peak 12/60s)  users=admin,root
    !! Successful login after failed attempts: investigate this host/account
    block with: sudo ufw deny from 203.0.113.45
\[HIGH] 198.51.100.7  failures=7 (peak 7/60s)  users=test
```

## How it works

1. Regex-parse `Failed password` and `Accepted` events from sshd
2. Group by source IP and slide a time window over failures
3. Correlate later successful logins from the same IP
4. Rank by severity

## Defensive use only

Run this only on logs from systems you own or are authorized to monitor. Sample IPs use documentation ranges (RFC 5737).

## Ideas for improvement

* GeoIP / threat-intel lookup
* Email or Telegram alerts
* Real-time log tailing
* Fail2ban-style auto-blocking
* Web dashboard (Flask)

## License

MIT

