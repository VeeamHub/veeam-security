# Veeam Cortex XSOAR Playbooks

This folder contains various Cortex XSOAR playbooks for Veeam.

## About the API command used

Several of these playbooks use the `veeam-vbr-general-api-request` command, which was introduced with version 2 of the Veeam App for Palo Alto Networks XSOAR. This command lets a playbook send a generic HTTP request to any available Veeam REST API endpoint, rather than being limited to the specific pre-built commands. This makes it possible to build playbooks around API calls that don't have a dedicated command yet.

## Disclaimer

These playbooks are **not** official playbooks provided by Veeam. They were built independently and are not supported or endorsed by Veeam.
