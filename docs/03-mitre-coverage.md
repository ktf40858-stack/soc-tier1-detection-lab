# 3. ATT&CK coverage — and the gaps

Coverage claims are usually inflated. This one is deliberately small and honest: six
detections cover six techniques on one platform.

## Covered

| Tactic | Technique | ID | Rule | Confidence |
|---|---|---|---|---|
| Execution | PowerShell | T1059.001 | SOC-001 | High — validated |
| Credential Access | Brute Force: Password Guessing | T1110.001 | SOC-002 | High — validated |
| Credential Access | Brute Force: Password Spraying | T1110.003 | SOC-002b | Medium — validated in lab, thresholds untested at scale |
| Command and Control | Ingress Tool Transfer | T1105 | SOC-003 | High — validated |
| Persistence | Registry Run Keys | T1547.001 | SOC-004 | Medium — noisy without a baseline |
| Persistence / PrivEsc | Scheduled Task | T1053.005 | SOC-005 | Medium — validated |
| Defense Evasion | Signed Binary Proxy: Rundll32 | T1218.011 | SOC-006 | High — validated |

## Not covered, and I know it

Listing the gaps is part of the exercise. A Tier 1 analyst who cannot say what their
detection stack is blind to is a liability.

| Gap | Why it is not here | What it would take |
|---|---|---|
| Credential dumping (T1003) | Sysmon EID 10 (process access) is very noisy without heavy filtering | A tuned EID 10 config targeting lsass handles specifically |
| Lateral movement (T1021) | Single-endpoint lab — there is nothing to move to | A second Windows VM and a domain controller |
| Kerberos attacks (T1558) | No Active Directory in this build | AD DS on a Windows Server VM |
| Cloud identity (T1078.004) | Out of scope for an endpoint lab | Entra ID sign-in logs, a different data source entirely |
| Exfiltration (T1041) | No network sensor | Zeek or Suricata on a span port |

The AD gap is the biggest one and it is the next build: a domain controller turns roughly
half the ATT&CK enterprise matrix from unreachable to reachable.

## On coverage percentages

I have not put a percentage on this. Counting techniques as covered because one rule
mentions them is how coverage dashboards end up saying 80% while missing the intrusion.
Seven techniques, each fired and confirmed, is a smaller and truer claim.
