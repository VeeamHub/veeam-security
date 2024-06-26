import argparse
import requests
import urllib3

# General Variables - Change if necessary
x_api_version = "1.1-rev1"
api_version   = "v1"

# Disable insecure request warnings - Not recommended in production environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def retrieve_password(args):
    url = f"https://{args.cyCCPSrv}/AIMWebservice/api/Accounts?AppID={args.cyAppId}&Safe={args.cySafe}&Object=Operating%20System-WinServerLocal-{args.vbrServer}-{args.vbrUser}"

    try:
        # Make the request with SSL certificate verification disabled
        response = requests.get(url, verify=False)

        if response.status_code == 200:
            result = response.json()
            password = result.get('Content')
            return password
        else:
            print(f"Failed to retrieve password from CCP. Status code: {response.status_code}")
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None

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

    try:
        response = requests.post(token_url, headers=headers, data=body, verify=False)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        print(f"Error while retrieving bearer token: {e}")
        return None

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

        # Retrieve the password
        vbr_password = retrieve_password(args)

        if vbr_password:
            print("Password successfully retrieved from CyberArk Safe")
        else:
            print("Password not found or retrieval failed.")

        bearer_token = connect_veeam_rest_api(args.vbrUser, vbr_password, args.vbrServer)
        print("Bearer Token successfully retrieved from VBR")
       
        malware_events = get_veeam_rest_api(bearer_token, args.vbrServer)
        print("Malware detection events successfully retrieved")

        print("Last 10 events")
        print("------------------------------------------------------------------------------")
        print("TimeUtc                   | Machine            | Severity  | Details")
        print("------------------------------------------------------------------------------")
        for entry in sorted(malware_events.get("data", []), key=lambda x: x.get("detectionTimeUtc", ""), reverse=True)[:10]:
            time_utc = entry.get('detectionTimeUtc', '').ljust(25)
            machine  = entry.get('machine', {}).get('displayName', '').ljust(18)
            severity = entry.get('severity', '').ljust(9)
            details  = entry.get('details', '')
            print(f"{time_utc} | {machine} | {severity} | {details}")

    except Exception as e:
        print(f"Error: {e}")
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Retrieve password using CyberArk Password SDK.')
    parser.add_argument('-vbrUser', type=str, required=True, help='Username for VBR')
    parser.add_argument('-vbrServer', type=str, required=True, help='Server for VBR')
    parser.add_argument('-cyCCPSrv', type=str, required=True, help='')
    parser.add_argument('-cyAppId', type=str, required=True, help='CyberArk Application ID')
    parser.add_argument('-cySafe', type=str, required=True, help='CyberArk Safe')

    args = parser.parse_args()
    main(args)
