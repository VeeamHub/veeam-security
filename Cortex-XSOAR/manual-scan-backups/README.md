# Manual Start Scan Backups

## What this playbook does

This playbook lets an analyst manually kick off a malware scan of a Veeam backup, using either Veeam Threat Hunter, an AV engine or a YARA rule. It waits for the scan to finish and reports whether it succeeded or failed.

## How it works

The playbook starts by asking the analyst for a hostname to scan, along with an optional choice of which Veeam Backup & Replication instance to use. It then queries Veeam for the most recent restore point of that host. If no restore point is found, the playbook stops and finishes right away.

If a restore point exists, the playbook looks up the matching backup object ID for that hostname, then branches into one of two paths depending on the scan type. On the YARA path, it fetches all available YARA rules, asks the analyst to pick one, and starts a scan using that rule. On the AV Scan path, it starts a scan directly using the antivirus engine, with no extra selection needed.

Once the scan is started, the playbook waits for it to finish by repeatedly polling the scan session (using the built-in `GenericPolling` sub-playbook) until it's no longer running. When the session completes, the playbook checks the result: if it ended in "Success" or "Warning," it's marked as **Success**; otherwise, it's marked as **Failed**. Either way, the playbook then ends.

## What you need before running it

- A hostname of the machine whose backup you want to scan.
- A configured **VBR REST API** integration instance in your XSOAR/Cortex environment.
- If you want a YARA scan: at least one YARA rule already set up in Veeam.



## Notes

- The scan always uses the **most recent** restore point (`scanMode: MostRecent`).
- Only one of "AV Scan" or "YARA" runs per execution — never both.
- If no restore points are found for the hostname, the playbook exits early without starting any scan.
