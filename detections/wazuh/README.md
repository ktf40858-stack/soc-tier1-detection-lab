# Wazuh rules

`local_rules.xml` is the Wazuh translation of the Sigma rules in [`../sigma/`](../sigma/).

## Deploy

```bash
# on the Wazuh manager
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest      # validate before restarting
sudo /var/ossec/bin/wazuh-control restart
```

`wazuh-logtest` is not optional: a malformed regex in a custom rule stops the analysis
daemon from starting, and the manager then silently drops events.

## Rule ID map

| Wazuh ID | Detection | Level | Parent |
|---|---|---|---|
| 100001 | SOC-001 encoded PowerShell | 12 | 61603 |
| 100002 | SOC-001 tuning (management agent) | 0 | 100001 |
| 100003 | SOC-003 LOLBin download | 12 | 61603 |
| 100004 | SOC-006 rundll32 no args | 12 | 61603 |
| 100005 | SOC-006 rundll32 from Office | 12 | 61603 |
| 100006 | SOC-005 scheduled task | 10 | 61603 |
| 100007 | SOC-004 Run key persistence | 10 | 61614 |
| 100008 | SOC-004 tuning (installers) | 0 | 100007 |
| 100010 | SOC-002 brute force (10 in 5 min) | 10 | 60122 |
| 100011 | SOC-002 password spraying (8 accounts in 10 min) | 12 | 60122 |

## Two things worth pointing out

**Level 0 is how you tune in Wazuh.** Rules 100002 and 100008 are children of the detection
they suppress. Writing the exception as its own rule keeps the original detection readable
and leaves the exception visible in the ruleset — better than growing a regex nobody can
review six months later.

**Brute force and password spraying are not the same rule.** 100010 groups on the source
address and counts events; 100011 groups on the source address and requires the target
account to *differ* (`different_field`). Spraying stays under any per-account lockout
threshold by design, so a rule that only counts failures per account never sees it.
