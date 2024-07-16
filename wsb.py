import requests
import pandas as pd
import csv
import ast
import re
import glob
import unicodedata
import json
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from msal import ConfidentialClientApplication
import os

# Load environment variables
load_dotenv()

# Azure AD App Registration details from .env file
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
tenant_id = os.getenv('TENANT_ID')
authority = f'https://login.microsoftonline.com/{tenant_id}'
scope = ['https://graph.microsoft.com/.default']

# Function to get access token using MSAL
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
    other_count = 0

    for device in data.get('value', []):
        compliance_state = device.get('complianceState')
        
        if compliance_state == 'compliant':
            compliant_count += 1
        elif compliance_state == 'noncompliant':
            non_compliant_count += 1
        else:
            other_count += 1

    return compliant_count, non_compliant_count, other_count

# Function to get alerts from the Microsoft 365 API
def get_alerts(token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    start_date = (datetime.utcnow() - timedelta(days=14)).strftime('%Y-%m-%dT%H:%M:%SZ')
    alerts_url = f'https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=createdDateTime ge {start_date}'
    alerts_r = requests.get(alerts_url, headers=headers)
    alerts_r.raise_for_status()  # Check for errors
    return alerts_r.json()['value']

# Function to save the alerts data to a CSV file
def save_alerts_to_csv(alerts_data, filename='Alerts - Microsoft 365 security.csv'):
    df = pd.DataFrame(alerts_data)
    columns_to_keep = ['status', 'evidence', 'title', 'createdDateTime']
    df = df[columns_to_keep]
    for column in df.columns:
        df[column] = df[column].astype(str).str.replace(r'\n|\r', ' ', regex=True)
        df[column] = df[column].str.encode('utf-8').str.decode('utf-8')
        df[column] = df[column].str.replace(r'\u200b', '')
    df.to_csv(filename, index=False, quoting=csv.QUOTE_ALL)

# Define the regular expressions for each field
regex_mappings = {
    'ip_address': r"'ipInterfaces': \['([^']+)'(?:, '[^']+')*\]",
    'asset': r"'deviceDnsName': '([^']+)'|'accountName': '([^']+)'"
}

# Alert names to exclude from the report
excluded_alert_names = {
    "Email reported by user as junk",
    "Suspicious Email Forwarding Activity",
    "Email reported by user as malware or phish",
    "Anonymous IP address",
    "Phish delivered due to an ETR override",
    "Email messages from a campaign removed after delivery",
    "Email reported by user as not junk",
    "Email messages removed after delivery",
    "Email messages containing malicious URL removed after delivery",
    "Email messages containing malicious file removed after delivery",
    "DLP policy",
    "Anomalous Token"
}

excluded_prefixes = ["DLP policy"]

# Function to extract data using regex
def extract_data(alert_str):
    extracted_data = defaultdict(list)
    try:
        alert_data = ast.literal_eval(alert_str)
    except ValueError as e:
        print(f"Error parsing alert string: {e}")
        return extracted_data

    for field, regex in regex_mappings.items():
        matches = re.findall(regex, alert_str)
        if matches:
            for match in matches:
                if isinstance(match, tuple):
                    extracted_data[field].append(next(s for s in match if s))
                else:
                    extracted_data[field].append(match)

    return extracted_data

# Function to clean up field data
def clean_up_field(data):
    if isinstance(data, list):
        data = '; '.join(data).replace("'", "")
    if isinstance(data, str):
        data = unicodedata.normalize('NFKD', data).encode('ascii', 'ignore').decode('ascii', 'ignore').strip()
        data = data.strip("'\"").replace('â€‹', '')
    return data

# Function to save processed data to CSV
def save_to_csv(processed_alerts, file_path):
    if not processed_alerts:
        print("No processed alerts to save.")
        return

    df = pd.DataFrame(processed_alerts)
    desired_column_order = ['title', 'status', 'asset', 'ip_address', 'createdDateTime']
    df = df.reindex(columns=desired_column_order)
    column_renames = {
        'title': 'Alert',
        'status': 'Status',
        'asset': 'Assets',
        'ip_address': 'IP Addresses',
        'createdDateTime': 'DateTime'
    }
    df.rename(columns=column_renames, inplace=True)
    df.to_csv(file_path, index=False, quoting=csv.QUOTE_ALL)

# Helper function to check if a date is within the specified range
def is_date_in_range(date_str, start_date, end_date):
    date_without_microseconds = date_str.split('.')[0]
    date_without_timezone = date_without_microseconds.replace('Z', '')
    date = datetime.strptime(date_without_timezone, '%Y-%m-%dT%H:%M:%S')
    end_date_inclusive = end_date + timedelta(days=1)
    return start_date <= date < end_date_inclusive

# Function to read the CSV file and extract the alerts
def process_alerts(csv_file_path, start_date, end_date):
    processed_alerts = []
    alert_type_counts = defaultdict(int)
    malicious_url_count = 0
    malicious_file_count = 0
    phish_report_count = 0
    important_alerts_count = 0

    excluded_from_count = {
        "Email messages containing malicious URL removed after delivery",
        "Email messages containing malicious file removed after delivery",
        "Email reported by user as malware or phish"
    }

    with open(csv_file_path, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            alert_str = row.get('evidence', '')
            extracted_data = extract_data(alert_str)

            for key in extracted_data.keys():
                extracted_data[key] = clean_up_field(extracted_data[key])

            title = clean_up_field(row.get('title', ''))
            if 'createdDateTime' in row and not is_date_in_range(row['createdDateTime'], start_date, end_date):
                continue

            alert_data = {**row, 'title': title, **extracted_data}
            alert_data.pop('evidence', None)

            # Check if the title should be excluded
            exclude = False
            if title in excluded_alert_names:
                exclude = True
            else:
                for prefix in excluded_prefixes:
                    if title.startswith(prefix):
                        exclude = True
                        break

            if not exclude and title not in excluded_from_count:
                alert_type_counts[title] += 1
                important_alerts_count += 1  # Count as important alert

                # Add to processed_alerts only if it's an important alert
                processed_alerts.append(alert_data)

            # Count specific alert types for later use
            if title == "Email messages containing malicious URL removed after delivery":
                malicious_url_count += 1
            elif title == "Email messages containing malicious file removed after delivery":
                malicious_file_count += 1
            elif title == "Email reported by user as malware or phish":
                phish_report_count += 1

    return processed_alerts, alert_type_counts, malicious_url_count, malicious_file_count, phish_report_count, important_alerts_count

# Function to extract and write high-risk devices to a temp file
def extract_high_risk_devices(token):
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    alerts_url = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
    alerts_r = requests.get(alerts_url, headers=headers)
    alerts_r.raise_for_status()  # Check for errors
    with open('temp_alerts_data.json', 'w') as file:
        file.write(alerts_r.text)
    high_risk_devices = []
    with open('temp_alerts_data.json', 'r') as file:
        file_content = file.read()
        matches = re.findall(r'\{[^{]*"riskScore":\s*"high"[^{]*\}', file_content)
        high_risk_devices.extend(matches)
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

# Integrated main function
def main():
    # Delete the existing CSV files
    api_csv_file = 'Alerts - Microsoft 365 security.csv'
    if os.path.exists(api_csv_file):
        os.remove(api_csv_file)
        print(f"Deleted file: {api_csv_file}")
    else:
        print(f"File not found, skipping deletion: {api_csv_file}")

    output_csv_pattern = 'MS Def Important Alerts - *.csv'
    for file in glob.glob(output_csv_pattern):
        os.remove(file)
        print(f"Deleted file: {file}") 

    access_token = get_access_token(client_id, client_secret, authority, scope)
    if access_token:
        alerts_data = get_alerts(access_token)
        save_alerts_to_csv(alerts_data)

        # Prompt for the date range
        start_date_str = input("\nPlease enter start date (YYYY-MM-DD): ")
        end_date_str = input("Please enter end date (YYYY-MM-DD): ")

        # Convert string dates to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        # Process the CSV with user input
        processed_alerts, alert_type_counts, malicious_url_count, malicious_file_count, phish_report_count, important_alerts_count = process_alerts('Alerts - Microsoft 365 security.csv', start_date, end_date)

        # Print counts of each alert type
        print("\nAlert Type Counts:")
        for alert_type, count in alert_type_counts.items():
            print(f"{alert_type}: {count}")

        # Format the start and end dates for the filename
        formatted_start_date = start_date.strftime('%Y-%m-%d')
        formatted_end_date = end_date.strftime('%Y-%m-%d')
        output_filename = f"MS Def Important Alerts - {formatted_start_date}_{formatted_end_date}.csv"

        # Save the processed data to 'Cleaned Alerts.csv'
        save_to_csv(processed_alerts, output_filename)

        print(f"\nEmail messages containing malicious URL removed after delivery: {malicious_url_count}")
        print(f"Email messages containing malicious file removed after delivery: {malicious_file_count}")
        print(f"Email reported by user as malware or phish: {phish_report_count}")
        print(f"\nImportant Alerts: {important_alerts_count}")
        print(f"\nData saved to '{output_filename}' successfully!")

        extract_high_risk_devices(access_token)
        unique_high_risk_count = deduplicate_high_risk_devices()

        # Read and print the list of unique high-risk devices
        with open('high_risk_devices.json', 'r') as file:
            device_data = json.load(file)
            unique_devices = set()
            for device_info_str in device_data:
                device_info = json.loads(device_info_str)
                unique_devices.add(device_info.get('deviceDnsName', ''))
            print("\nList of Unique High-Risk Devices:")
            for device in unique_devices:
                print(device)

            print(f"\nCount of Unique High-Risk Devices: {unique_high_risk_count}")

        # Fetch and count device compliance data
        data = fetch_device_compliance_data(access_token)
        compliant_count, non_compliant_count, other_count = count_device_compliance(data)
        
        print(f"\nCompliant Devices: {compliant_count}")
        print(f"Non-Compliant Devices: {non_compliant_count}")
        print(f"Other Devices: {other_count}")

        # Delete the temporary files
        os.remove('temp_alerts_data.json')
        os.remove('high_risk_devices.json')
    else:
        print("Failed to obtain access token")

if __name__ == "__main__":
    main()