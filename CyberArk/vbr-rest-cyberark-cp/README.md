# VBR REST API / CyberArk Credential Provider (CP) / PowerShell & Python Script

## Version Information
~~~~
Version: 1.0 (May 2nd, 2024)
Author: Stephan "Steve" Herzig
~~~~

## Purpose
These scripts can be used as an example to retrieve a password for a specific user from CyberArk using the CyberArk CLI Application Password SDK. If successful, the script requests a bearer token from the Veeam Backup & Replication API with the returned password and then queries the Veeam Backup & Replcation API for the last 10 malware detection events.

## Parameters

- `vbrUser`
  - _(Mandatory)_ Username for accessing the Veeam Backup & Replication (VBR) server.

- `vbrServer`
  - _(Mandatory)_ The hostname or IP address of the VBR server. This value depends on the given address in the account properties.

- `cyAppId`
  - _(Mandatory)_ Represents the CyberArk application ID used for CyberArk integration. 
    The application ID identifies an application to CyberArk PAM-Self hosted or Privilege Cloud. It needs to be granted sufficient privileges to retrieve all the secrets it needs.
    The currently supported authentication methods for application authentication are "machine addresses" and "OS users".

- `cySafe`
  - _(Mandatory)_ Represents the name of the CyberArk safe where credentials are stored.

- `refreshCache`
  - A switch parameter to force a cache refresh.

## Example: 
```powershell
PS>.\vbr-rest-cyberark-cp.ps1 -vbrUser Administrator -vbrServer vbr-server-01 -cyAppId VBR_AppID -cySafe backup-creds
```

```python
Shell>python vbr-rest-cyberark-cp.py -vbrUser Administrator -vbrServer vbr-server-01 -cyAppId VBR_AppID -cySafe backup-creds
```

## Notes
The Python modules argparse, requests, subprocess, os and urllib3 are required for the Python scripts. These may need to be installed using pip (Package installer for Python). Urllib3 is only required for ignoring self-signed certificates.

These scripts have been tested with the following versions of the corresponding software:

- Veeam Backup & Replication V12.1.1
- Credential Provider ApplicationPasswordSdk 13.0

**script vbr-rest-cyberark-cp-linux.py (Python on Linux) could not be fully tested yet**

**Please note these scripts are unofficial and are not created nor supported by Veeam Software.**

## Version History
*  1.0
    * Initial Release
