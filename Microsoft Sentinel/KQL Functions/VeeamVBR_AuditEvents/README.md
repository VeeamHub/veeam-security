# VeeamVBR_AuditEvents

Veeam Backup & Replication can send its events to the Veeam App for Microsoft Sentinel Log Analytics workspace by syslog. They land in the `Syslog` table, but all the useful details are packed into a single text column, `SyslogMessage`. That makes the raw data hard to read and almost impossible to filter or report on.

The KQL function `VeeamVBR_AuditEvents` turns those raw messages into a clean, readable table. For each Veeam event it pulls out the event ID and gives it a plain name, for example "User Authorization Denied" or "Restore Point Deleted". It sorts each event into a category such as Access, MFA, Users, Four-Eyes, Deletion, Credentials, Malware, Restore or Config. It also adds separate columns for the most important details: who did it (user and SID), from where (source IP address), on what (VM, job or object), the operation, the reason and the full message. All remaining details stay available in one extra column, so nothing is lost.

The event list covers 71 events that matter for security and compliance. 

## Where it helps

- **Spotting attacks early.** Failed logins, wrong MFA codes and MFA being switched off become visible at a glance, including the source IP address.
- **Protecting the backups.** Deleted restore points, jobs or repositories, failed deletion attempts, changed encryption passwords and VMs quietly excluded from backup are easy to find. Attackers often target exactly these before ransomware strikes.
- **Audit trail.** Logins, changes to users, roles and MFA, deletions, credential changes, four-eyes approvals and configuration changes are all recorded with the user, the time and the affected object. Restores are covered at session level: the log shows who mounted which restore point of which machine, and why. Only the individual files copied during a file-level restore are not part of syslog. These come from Veeam's restore audit files, which are collected separately and can be matched to the syslog events by user and time.
- **Building alerts and dashboards.** Because the output is a clean table, it can be used directly in alert rules, workbooks or reports without further parsing.

## How to use it

Save the query from `VeeamVBR_AuditEvents.kql` in the Log Analytics workspace as a function named `VeeamVBR_AuditEvents`. Simple filters can then be added at the end, such as limiting the results to a time range, a category or a single event ID:

```kql
VeeamVBR_AuditEvents
| where EventTime > ago(7d)
| where Category in ("Access", "MFA", "Deletion")
```
