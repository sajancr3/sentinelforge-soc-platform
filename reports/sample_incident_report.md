# SentinelForge Incident Report

## Incident Summary

SentinelForge detected repeated suspicious activity from source IP `192.168.64.4` targeting monitored host `192.168.64.6`.

The activity included network reconnaissance and repeated SSH authentication failures. Events were correlated by source IP and escalated based on cumulative risk.

## Detection Sources

- Suricata EVE JSON
- Linux auth.log
- Python correlation engine

## Timeline

| Time | Event | Source |
|---|---|---|
| 18:20:10 | Nmap scan alert detected | Suricata |
| 18:21:01 | SSH failed login attempt | auth.log |
| 18:21:04 | SSH failed login attempt | auth.log |
| 18:21:08 | SSH failed login attempt | auth.log |
| 18:21:16 | Brute-force pattern threshold reached | Correlation engine |

## MITRE ATT&CK Mapping

- T1046 - Network Service Discovery
- T1110 - Brute Force

## Risk Assessment

Risk Level: High

Reason:
- Multiple failed authentication attempts
- Network reconnaissance from same source IP
- Repeated suspicious behavior within short time window

## Recommended Response

- Validate whether source IP belongs to lab/authorized testing
- If unauthorized, block source IP at firewall
- Review SSH exposure and disable weak/default accounts
- Preserve logs for investigation
- Document incident and remediation

## Safety Note

Blocking was simulated because the source IP belonged to a controlled private lab network.
