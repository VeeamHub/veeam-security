import subprocess
import argparse
import os
import requests
import urllib3

# General Variables - Change if necessary
x_api_version = "1.1-rev1"
api_version   = "v1"

# Disable insecure request warnings - Do not use in production environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def retrieve_password(vbr_user, vbr_server, cy_app_id, cy_safe):
    cyberark_executable = r'/opt/CARKaim/sdk/clipasswordsdk'
    if not os.path.exists(cyberark_executable):
        raise FileNotFoundError(f"CyberArk Password SDK executable not found at '{cyberark_executable}'.")

    query = f'Safe={cy_safe};Folder=Root;Object=Operating System-WinServerLocal-{vbr_server}-{vbr_user}'
    query_with_quotes = f'Query="{query}"'

    command = [
        cyberark_executable,
        'GetPassword',
        '-p', f'AppDescs.AppID={cy_app_id}',
        '-p', query_with_quotes,
        '-o', 'Password'
    ]

    print("Command to be executed:", " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout.strip()

def refresh_cache():
    app_prv_mgr_executable = r'/opt/CARKaim/bin/appprvmgr'
    if not os.path.exists(app_prv_mgr_executable):
        raise FileNotFoundError(f"AppPrvMgr.exe not found at '{app_prv_mgr_executable}'.")

    subprocess.run([app_prv_mgr_executable, 'RefreshCache'], check=True)

def connect_veeam_rest_api(vbr_user, vbr_password, vbr_server):
    api_url = f"https://{vbr_server}:9419"
    token_url = f"{api_url}/api/oauth2/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-api-version": x_api_version,
        "accept": "application/json"
    }

    body = {
        "grant_type": "password",
        "username": vbr_user,
        "password": vbr_password,
        "refresh_token": " ",
        "rememberMe": " "
    }

    response = requests.post(token_url, headers=headers, data=body, verify=False)
    response.raise_for_status()

    return response.json()["access_token"]

def get_veeam_rest_api(token, vbr_server):
    api_url = f"https://{vbr_server}:9419"
    app_uri = f"api/{api_version}/malwareDetection/events/"
    headers = {
        "accept": "application/json",
        "x-api-version": x_api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(f"{api_url}/{app_uri}", headers=headers, verify=False)
    response.raise_for_status()

    return response.json()

def main(args):
    try:
        if args.refreshCache:
            refresh_cache()

        vbr_password = retrieve_password(args.vbrUser, args.vbrServer, args.cyAppId, args.cySafe)
        print("Password successfully retrieved from CyberArk Safe")

        bearer_token = connect_veeam_rest_api(args.vbrUser, vbr_password, args.vbrServer)
        print("Bearer Token successfully retrieved")

        malware_events = get_veeam_rest_api(bearer_token, args.vbrServer)
        print("Malware detection events successfully retrieved")

        print("Last 10 events")
        print("------------------------------------------------------------------------------")
        print("TimeUtc                   | Machine            | Severity | Details")
        print("------------------------------------------------------------------------------")
        for entry in sorted(malware_events.get("data", []), key=lambda x: x.get("detectionTimeUtc", ""), reverse=True)[:10]:
            time_utc = entry.get('detectionTimeUtc', '').ljust(25)
            machine  = entry.get('machine', {}).get('displayName', '').ljust(18)
            severity = entry.get('severity', '').ljust(9)
            details  = entry.get('details', '')
            print(f"{time_utc} | {machine} | {severity} | {details}")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Retrieve password using CyberArk Password SDK and interact with Veeam REST API.')
    parser.add_argument('-vbrUser', type=str, required=True, help='Username for VBR')
    parser.add_argument('-vbrServer', type=str, required=True, help='Server for VBR')
    parser.add_argument('-cyAppId', type=str, required=True, help='CyberArk Application ID')
    parser.add_argument('-cySafe', type=str, required=True, help='CyberArk Safe')
    parser.add_argument('--refreshCache', action='store_true', help='Refresh the cache')

    args = parser.parse_args()
    main(args)
