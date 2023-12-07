import os
import requests
import re
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Retrieve environment variables
tenant_id = os.getenv('TENANT_ID')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')

# Get access token
def get_access_token(tenant_id, client_id, client_secret):
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    token_r = requests.post(token_url, data=token_data)
    token_r.raise_for_status()  # Check for errors
    return token_r.json().get('access_token')

# Function to extract and write high-risk devices to a temp file
def extract_high_risk_devices(token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    alerts_url = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
    alerts_r = requests.get(alerts_url, headers=headers)
    alerts_r.raise_for_status()  # Check for errors

    # Write all data to a temp file
    with open('temp_alerts_data.json', 'w') as file:
        file.write(alerts_r.text)

    # Use regex to extract devices with 'riskScore': 'high'
    high_risk_devices = []
    with open('temp_alerts_data.json', 'r') as file:
        file_content = file.read()
        matches = re.findall(r'\{[^{]*"riskScore":\s*"high"[^{]*\}', file_content)
        high_risk_devices.extend(matches)

    # Write high-risk devices to another file
    with open('high_risk_devices.json', 'w') as file:
        json.dump(high_risk_devices, file, indent=4)

    return len(high_risk_devices)

# Function to deduplicate and count high-risk devices from "high_risk_devices.json"
def deduplicate_high_risk_devices():
    high_risk_devices = set()
    with open('high_risk_devices.json', 'r') as file:
        device_data = json.load(file)
        for device_info_str in device_data:
            device_info = json.loads(device_info_str)
            high_risk_devices.add(device_info.get('deviceDnsName', ''))

    return len(high_risk_devices)

# Main execution
if __name__ == "__main__":
    token = get_access_token(tenant_id, client_id, client_secret)
    extract_high_risk_devices(token)

    unique_high_risk_count = deduplicate_high_risk_devices()

    # Read and print the list of unique high-risk devices
    with open('high_risk_devices.json', 'r') as file:
        device_data = json.load(file)
        unique_devices = set()
        for device_info_str in device_data:
            device_info = json.loads(device_info_str)
            unique_devices.add(device_info.get('deviceDnsName', ''))
        print("List of Unique High-Risk Devices:")
        for device in unique_devices:
            print(device)

    print(f"\nCount of Unique High-Risk Devices: {unique_high_risk_count}")

    # Delete the temporary files
    os.remove('temp_alerts_data.json')
    os.remove('high_risk_devices.json')