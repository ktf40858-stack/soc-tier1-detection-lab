# 1. Building the lab

Target: a working detection pipeline on one machine — endpoint telemetry in, alerts out.

## What you need

| | |
|---|---|
| Host | 16 GB RAM, 60 GB free disk, virtualisation enabled |
| Manager | Ubuntu Server 22.04 VM, 4 GB RAM, 2 vCPU — runs Wazuh 4.9 in Docker |
| Endpoint | Windows 11 VM, 4 GB RAM — Wazuh agent + Sysmon |
| Network | Host-only / internal network, `192.168.56.0/24` in my build |

Cost: nothing. Wazuh is open source and both OS images are free (Windows 11 dev VM from
Microsoft, 90-day evaluation).

## 1.1 Wazuh manager

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node

# generate the internal certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# CHANGE THE DEFAULT PASSWORDS BEFORE THE FIRST START
# docker-compose.yml ships with admin/SecretPassword and wazuh-wui/MyS3cr37P450r.*-
# replace both, in docker-compose.yml and in config/wazuh_indexer/internal_users.yml
docker compose up -d
```

Two of those default credentials are published in the Wazuh documentation and are the first
thing anyone scanning port 443 will try. Changing them is step one, not a hardening task for
later. In this repo the values live in a git-ignored `.env`.

Dashboard: `https://<MANAGER_IP>` — expect a self-signed certificate warning on a lab build.

## 1.2 Sysmon on the endpoint

Windows' native process-creation event (4688) does not give you the parent command line,
hashes, or the network and registry events half of these detections need. Sysmon does.

```powershell
# elevated PowerShell on the Windows VM
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

Use [`../sysmon/sysmonconfig.xml`](../sysmon/sysmonconfig.xml) from this repo. Verify:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## 1.3 Wazuh agent

Install the agent, point it at the manager, then tell it to forward the Sysmon channel.
In `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720]</query>
</localfile>
```

Restart the agent, then confirm on the manager that events arrive:

```bash
docker exec -it single-node-wazuh.manager-1 \
  tail -f /var/ossec/logs/archives/archives.json | grep sysmon
```

If nothing arrives, it is almost always one of three things: agent not registered
(`/var/ossec/bin/agent_control -l`), port 1514/TCP blocked, or `<logall_json>` disabled in
`ossec.conf` on the manager so the archive file stays empty.

## 1.4 Load the detections

```bash
sudo cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo /var/ossec/bin/wazuh-control restart
```

## 1.5 Prove each rule fires

Do not trust a rule you have not triggered. Every detection here was fired with the Atomic
Red Team test listed in [`../attack-simulation/atomic-tests.md`](../attack-simulation/atomic-tests.md),
and the alert confirmed in the dashboard before the rule was considered done.

## Build time

About 4 hours the first time, most of it waiting on the Windows VM and the indexer's first
start. Rebuilding from these notes: under an hour.
