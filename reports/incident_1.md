
# INCIDENT REPORT

## Basic Information
- Date: 2026-04-26 08:25:26.602015
- Incident Type: SSH Brute Force Detected
- Severity: High

## Source
- Source IP: 192.168.1.10
- Attempts: 5

## MITRE ATT&CK
- Technique: T1110 - Brute Force

## Summary
Multiple failed SSH login attempts detected, indicating a brute force attack.

## Impact
Potential unauthorized access attempt on the system.

## Recommended Actions
- Block source IP and review authentication logs

## Analyst Notes
- Investigate login attempts
- Check if any login succeeded
- Monitor for repeated activity
