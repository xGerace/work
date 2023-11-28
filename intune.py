import requests
from msal import ConfidentialClientApplication
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Azure AD App Registration details from .env file
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
tenant_id = os.getenv('TENANT_ID')
authority = f'https://login.microsoftonline.com/{tenant_id}'
scope = ['https://graph.microsoft.com/.default']

# Function to get access token
def get_access_token(client_id, client_secret, authority, scope):
    app = ConfidentialClientApplication(client_id, client_secret, authority=authority)
    token_response = app.acquire_token_for_client(scopes=scope)
    return token_response.get('access_token', None)

# Function to fetch device compliance data
def fetch_device_compliance_data(access_token):
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    headers = {'Authorization': 'Bearer ' + access_token}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to count compliant and non-compliant devices
def count_device_compliance(data):
    compliant_count = 0
    non_compliant_count = 0
    other_count = 0  # Count for any other states

    for device in data.get('value', []):
        compliance_state = device.get('complianceState')
        
        if compliance_state == 'compliant':
            compliant_count += 1
        elif compliance_state == 'noncompliant':
            non_compliant_count += 1
        else:
            # Increment the count for any other state
            other_count += 1

    return compliant_count, non_compliant_count, other_count

# Main function
def main():
    access_token = get_access_token(client_id, client_secret, authority, scope)
    if access_token:
        data = fetch_device_compliance_data(access_token)

        # Updated to handle the new "other" category
        compliant_count, non_compliant_count, other_count = count_device_compliance(data)
        
        print(f"Compliant Devices: {compliant_count}")
        print(f"Non-Compliant Devices: {non_compliant_count}")
        print(f"Other Devices: {other_count}")  # Print the count of "other" devices
    else:
        print("Failed to obtain access token")

if __name__ == '__main__':
    main()
