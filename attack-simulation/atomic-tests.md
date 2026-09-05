# Validating the detections

A rule that has never fired is a guess. Every detection in this repo was triggered on purpose
and confirmed in the dashboard before it was considered finished.

Simulation uses [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

## Setup

```powershell
# On the Windows VM only. Never on a machine you care about.
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module Invoke-AtomicRedTeam
```

Snapshot the VM first. Several of these leave persistence behind, and the cleanup command is
best-effort, not a guarantee.

## The tests, and what should fire

| Detection | Atomic test | Command | Expect |
|---|---|---|---|
| SOC-001 | T1059.001-1 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | Wazuh 100001, level 12 |
| SOC-002 | — | see the manual test below | Wazuh 100010 after 10 failures |
| SOC-002b | — | see the manual test below | Wazuh 100011 after 8 accounts |
| SOC-003 | T1105-1 (certutil) | `Invoke-AtomicTest T1105 -TestNumbers 1` | Wazuh 100003, level 12 |
| SOC-003 | T1105-6 (bitsadmin) | `Invoke-AtomicTest T1105 -TestNumbers 6` | Wazuh 100003 |
| SOC-004 | T1547.001-1 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | Wazuh 100007, level 10 |
| SOC-005 | T1053.005-1 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Wazuh 100006, level 10 |
| SOC-006 | T1218.011-1 | `Invoke-AtomicTest T1218.011 -TestNumbers 1` | Wazuh 100004 or 100005 |

Always clean up afterwards:

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

## Manual test for SOC-002

Atomic Red Team does not cover this one cleanly against a standalone Windows host, so it is
driven from the Linux VM. Both variants target a local account on the Windows VM over SMB.

```bash
# Brute force: one account, many attempts -> should trip 100010
for i in $(seq 1 15); do
  smbclient -L //<WINDOWS_VM_IP> -U testuser%wrongpass$i 2>/dev/null
done

# Spraying: many accounts, two attempts each -> should trip 100011, not 100010
for u in alice bob carol dave erin frank grace heidi; do
  smbclient -L //<WINDOWS_VM_IP> -U $u%Summer2026! 2>/dev/null
done
```

The second loop is the interesting one: it stays under any per-account lockout threshold, so
a rule that counts failures per account sees nothing. That is the whole point of rule 100011.

## Recording the result

For each test: the alert ID, the rule that fired, the level, and the time from execution to
alert. If nothing fires, the rule is wrong — check with `wazuh-logtest` against the raw event
before touching the lab:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste the raw JSON event, see which rule matches and at which level
```

Nine times out of ten the answer is that the field name in the rule does not match what the
decoder actually produced. `wazuh-logtest` shows you the decoded field names, which is faster
than guessing.

## Safety

Run these on an isolated lab VM with a snapshot taken beforehand. Do not run Atomic Red Team
on a production endpoint, on a domain-joined machine, or on anything you would mind
rebuilding. Some tests download real (defanged) tooling from the internet and will make your
AV very unhappy.
