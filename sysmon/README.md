# Sysmon configuration

`sysmonconfig.xml` is what makes the detections in this repo possible. Without it, the
Windows Security log gives you 4688 process creation without the parent command line, no
registry events, and no DNS — three of the six detections simply cannot be written.

## Install

```powershell
# elevated
C:\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml

# update an existing install
C:\Sysmon\Sysmon64.exe -c sysmonconfig.xml

# check what is loaded
C:\Sysmon\Sysmon64.exe -c
```

## Which events, and what they feed

| EID | Event | Feeds |
|---|---|---|
| 1 | Process creation | SOC-001, SOC-003, SOC-005, SOC-006 |
| 3 | Network connection | triage pivot — what did the process talk to |
| 11 | File create | triage pivot — what got staged on disk |
| 13 | Registry value set | SOC-004 |
| 22 | DNS query | triage pivot — the domain, before the IP rotates |

## Include vs exclude, and why it is chosen per event

Process creation uses **exclude**: on an endpoint you want every process, and you carve out
the handful of high-volume signed binaries. Network connection uses **include**: logging
every connection on a workstation floods the pipeline within minutes, so only the binaries
that have no business making outbound connections are logged.

Getting this backwards is the standard first mistake — an include-list on process creation
means you only ever detect what you already thought of.

## This is a lab config

It is deliberately more verbose than a fleet deployment: no exclusions for line-of-business
software, hashes on everything, DNS mostly unfiltered. For a real deployment, start from
[SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or
[Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular) and measure
event volume per endpoint before rolling it out.
