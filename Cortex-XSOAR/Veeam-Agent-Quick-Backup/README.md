# Veeam Agent Quick Backup

## What this playbook does

This playbook lets an analyst manually trigger a quick backup of a Veeam Agent-protected machine (Windows or Linux). It waits for the backup job to finish and reports whether it succeeded or failed.

## How it works

The playbook starts by asking the analyst for the hostname of the machine to back up and which VBR Veeam Backup & Replication instance to use. It then looks up the agent's info from Veeam by filtering on that hostname.

Based on the operating system found in that lookup, the playbook branches into one of two paths: if it's a Windows machine, it starts a Windows Agent Quick Backup; if it's Linux, it starts a Linux Agent Quick Backup. Both paths call the same underlying API endpoint, just with the matching computer type.

Once the backup job is started, the playbook pauses for 30 seconds before starting to poll the backup session repeatedly (using the built-in `GenericPolling` sub-playbook) until the job is no longer running. When the session finishes, the playbook fetches the session details and checks the result: if it ended in "Success" or "Warning," it's marked as **Success**; otherwise, it's marked as **Failed**. Either way, the playbook then ends.

## What you need before running it

- The hostname of the machine you want to back up.
- The machine must already be discovered/registered as a Veeam Agent in VBR.
- Quick backup can only be run for agents that have been successfully backed up at least once and have a full restore point.
- A configured VBR REST API integration instance in your XSOAR/Cortex environment.


## Notes
- The REST API Endpoint is available from version 13.1 (1.3-rev2)
