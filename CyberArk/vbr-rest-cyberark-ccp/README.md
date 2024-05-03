# VBR REST API / CyberArk Central Credential Provider (CCP) / Python Script

## Version Information
~~~~
Version: 1.0 (May 2nd, 2024)
Author: Stephan "Steve" Herzig
~~~~

## Purpose
This script can be used as an example to retrieve a password for a specific user from Central Credential Provider. It constructs a URL based on the provided parameters and sends a GET request to the specified endpoint. Upon receiving a successful response, it extracts and uses the password to request a bearer token from the Veeam Backup & Replication API with the returned password and then queries the Veeam Backup & Replcation API for the last 10 malware detection events.

## Parameters

- `vbrUser`
  - _(Mandatory)_ Username for the Veeam Backup & Replication (VBR) server.

- `vbrServer`
  - _(Mandatory)_ The hostname or IP address of the VBR server. This value depends on the given address in the account properties.

- `cyCCPSrv`
  - _(Mandatory)_ Specifies the CyberArk Central Credential Provider Server.

- `cyAppId`
  - _(Mandatory)_ Specifies the CyberArk Application ID.

- `cySafe`
  - _(Mandatory)_ Specifies the CyberArk Safe in which the credentials are stored.

## Example:
```python
Shell>python vbr-rest-api-cyberark-ccp.py -vbrUser Administrator -vbrServer vbr-server-01 -cyCCPSrv ccp-server-01 -cyAppId CCP_AppID -cySafe Backup-Creds
```
## Notes
The Python modules argparse, requests and urllib3 are required. These may need to be installed using pip (Package installer for Python). Urllib3 is only required for ignoring self-signed certificates.

This script has been tested with the following versions of the corresponding software:

- Veeam Backup & Replication V12.1.1
- Central Credential Provider 13.0.1

A PowerShell can be made available if there is demand for it.

**Please note these scripts are unofficial and are not created nor supported by Veeam Software.**

## Version History
*  1.0
    * Initial Release
