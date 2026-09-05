# SOC Tier 1 Detection Lab

A home SOC built to practice the work of a Tier 1 analyst end to end: collect endpoint
telemetry, write detections for it, trigger the behaviour on purpose, then triage the alert
with a written runbook.

Stack: **Wazuh 4.9 (single node, Docker)** + **Sysmon** on a Windows 11 endpoint +
**Sigma** rules translated to Wazuh, with **MITRE ATT&CK** mapping and **Atomic Red Team**
used to fire each detection.

> Everything here is reproducible on one machine with 16 GB of RAM. No credentials, no real
> hostnames and no production data are committed — see [Handling of secrets](#handling-of-secrets).

---

## Why this repo exists

Reading about detections is not the same as writing one, watching it fail, and fixing it.
Each detection in this repo went through the same loop:

```
hypothesis → what telemetry proves it → rule → fire the technique → check the alert → tune the FPs
```

The interesting part of the repo is not the rule files, it is the **tuning notes** and the
**runbooks**: what a Tier 1 analyst actually does with the alert at 3am.

## What is in here

| Folder | Contents |
|---|---|
| [`docs/`](docs/) | Lab build, detection engineering method, ATT&CK coverage matrix |
| [`detections/sigma/`](detections/sigma/) | 6 detections in Sigma (vendor-neutral) |
| [`detections/wazuh/`](detections/wazuh/) | The same rules as Wazuh `local_rules.xml`, with rule IDs |
| [`sysmon/`](sysmon/) | The Sysmon configuration the detections depend on |
| [`runbooks/`](runbooks/) | Triage runbooks — one per detection family |
| [`attack-simulation/`](attack-simulation/) | The Atomic Red Team tests used to validate each rule |

## Detections and coverage

| ID | Detection | Rule | ATT&CK | Data source | Runbook |
|---|---|---|---|---|---|
| SOC-001 | Encoded PowerShell command line | [sigma](detections/sigma/proc_creation_win_powershell_encodedcommand.yml) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Sysmon EID 1 | [RB-001](runbooks/RB-001-encoded-powershell.md) |
| SOC-002 | Failed logon burst (password spray / brute force) | [sigma](detections/sigma/auth_win_failed_logon_bruteforce.yml) | [T1110](https://attack.mitre.org/techniques/T1110/) | Security EID 4625 | [RB-002](runbooks/RB-002-failed-logon-bruteforce.md) |
| SOC-003 | LOLBin download (certutil / bitsadmin / curl) | [sigma](detections/sigma/proc_creation_win_lolbin_certutil_download.yml) | [T1105](https://attack.mitre.org/techniques/T1105/) | Sysmon EID 1 | [RB-003](runbooks/RB-003-lolbin-download.md) |
| SOC-004 | Run key persistence | [sigma](detections/sigma/registry_persistence_run_key.yml) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Sysmon EID 13 | [RB-004](runbooks/RB-004-persistence-run-key.md) |
| SOC-005 | Scheduled task created by a non-admin process | [sigma](detections/sigma/proc_creation_win_scheduled_task_creation.yml) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Sysmon EID 1 | [RB-004](runbooks/RB-004-persistence-run-key.md) |
| SOC-006 | rundll32 with no arguments / suspicious parent | [sigma](detections/sigma/proc_creation_win_rundll32_suspicious.yml) | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Sysmon EID 1 | [RB-003](runbooks/RB-003-lolbin-download.md) |

Full matrix with the gaps I know about: [`docs/03-mitre-coverage.md`](docs/03-mitre-coverage.md).

## Reproduce it

```bash
git clone https://github.com/ktf40858-stack/soc-tier1-detection-lab
cd soc-tier1-detection-lab
# 1. Build the lab (Wazuh manager + Windows endpoint + Sysmon)
#    -> docs/01-lab-build.md
# 2. Copy the detections into the manager
#    /var/ossec/etc/rules/local_rules.xml
# 3. Fire the techniques and confirm each alert
#    -> attack-simulation/atomic-tests.md
```

## Handling of secrets

No password, API key, certificate or real IP address is committed to this repository.
Everything environment-specific is a placeholder (`<WAZUH_MANAGER_IP>`, `<AGENT_KEY>`,
`${WAZUH_API_PASSWORD}`) and is read from `.env`, which is git-ignored. The default Wazuh
credentials are changed at install time — the step is in the build guide, not skipped.

## Credits

- Sysmon configuration derived from [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), trimmed to the events these detections use.
- Detection format: [SigmaHQ](https://github.com/SigmaHQ/sigma).
- Technique simulation: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
- Technique taxonomy: [MITRE ATT&CK](https://attack.mitre.org/).

## Related labs

The detections here are the reactive half. The preventive half lives in the other repos:

- [l2-attacks-and-mitigations](https://github.com/ktf40858-stack/l2-attacks-and-mitigations) — the Layer 2 attacks these
  detections would see coming off a switch, and the configuration that stops them first.
- [network-config-compliance](https://github.com/ktf40858-stack/network-config-compliance) — catching the misconfiguration
  before it ships, rather than alerting on it after.
- [zero-trust-sase-architecture](https://github.com/ktf40858-stack/zero-trust-sase-architecture) — the access model that
  shrinks what an alert can reach in the first place.

## Author

Kodjo Apedoh — Network & Cloud Security · Arlington, VA
CCNA · Fortinet NSE · Palo Alto SASE & Cloud Security
[LinkedIn](https://www.linkedin.com/in/kodjo-apedoh-03030990/) · [Other labs](https://github.com/ktf40858-stack)

## License

MIT — see [LICENSE](LICENSE).
