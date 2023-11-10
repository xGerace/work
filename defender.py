import os
import requests
import pandas as pd
import csv
import ast
import re
import glob
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
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
    # Convert the alerts data to a DataFrame
    df = pd.DataFrame(alerts_data)

    # Keep only the 'status', 'evidence', 'title', and 'createdDateTime' columns
    columns_to_keep = ['status', 'evidence', 'title', 'createdDateTime']
    df = df[columns_to_keep]

    # Replace newlines with spaces and handle special unicode characters
    for column in df.columns:
        df[column] = df[column].astype(str).str.replace(r'\n|\r', ' ', regex=True)
        df[column] = df[column].str.encode('utf-8').str.decode('utf-8')
        df[column] = df[column].str.replace(r'\u200b', '')  # Remove zero-width spaces

    # Save the filtered DataFrame to a CSV file
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
    "Email messages containing malicious URL removed after delivery",
    "Email messages containing malicious file removed after delivery"
}

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
            # Ensure only strings are appended
            for match in matches:
                if isinstance(match, tuple):
                    # Append the first non-empty string from the tuple
                    extracted_data[field].append(next(s for s in match if s))
                else:
                    extracted_data[field].append(match)

    return extracted_data

# Function to clean up field data
def clean_up_field(data):
    if isinstance(data, list):
        data = '; '.join(data).replace("'", "")
    if isinstance(data, str):
        # Normalize and remove non-ASCII characters
        data = unicodedata.normalize('NFKD', data).encode('ascii', 'ignore').decode('ascii', 'ignore').strip()
        data = data.strip("'\"").replace('â€‹', '')
    return data

# Function to save processed data to CSV
def save_to_csv(processed_alerts, file_path):
    if not processed_alerts:
        print("No processed alerts to save.")
        return

    # Create a DataFrame from the processed alerts
    df = pd.DataFrame(processed_alerts)

    # Rearrange columns to the desired order
    desired_column_order = ['title', 'status', 'asset', 'ip_address', 'createdDateTime']
    df = df.reindex(columns=desired_column_order)

    # Rename the columns to the desired names
    column_renames = {
        'title': 'Alert',
        'status': 'Status',
        'asset': 'Assets',
        'ip_address': 'IP Addresses',
        'createdDateTime': 'DateTime'
    }
    df.rename(columns=column_renames, inplace=True)

    # Save the DataFrame to a CSV file
    df.to_csv(file_path, index=False, quoting=csv.QUOTE_ALL)

# Function to read the CSV file and extract the alerts
def process_alerts(csv_file_path, start_date, end_date):
    processed_alerts = []
    malicious_url_count = 0
    malicious_file_count = 0
    phish_report_count = 0
    important_alerts_count = 0

    with open(csv_file_path, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            alert_str = row.get('evidence', '')
            extracted_data = extract_data(alert_str)

            # Clean up the extracted data
            for key in extracted_data.keys():
                extracted_data[key] = clean_up_field(extracted_data[key])

            # Clean up the title
            title = clean_up_field(row.get('title', ''))

            # Check if the createdDateTime is within the specified date range
            if 'createdDateTime' in row and not is_date_in_range(row['createdDateTime'], start_date, end_date):
                continue

            # Merge the cleaned title and the extracted data with the row data
            alert_data = {**row, 'title': title, **extracted_data}

            # Remove the evidence column from final output
            alert_data.pop('evidence', None)

            # Count specific alert types after cleaning the title
            if "Email messages containing malicious URL removed after delivery" in title:
                malicious_url_count += 1
            elif "Email messages containing malicious file removed after delivery" in title:
                malicious_file_count += 1
            elif "Email reported by user as malware or phish" in title:
                phish_report_count += 1

            # Check if the alert title is one of the excluded names
            if title in excluded_alert_names:
                continue

            important_alerts_count += 1
            processed_alerts.append(alert_data)

    return processed_alerts, malicious_url_count, malicious_file_count, phish_report_count, important_alerts_count

# Helper function to check if a date is within the specified range
def is_date_in_range(date_str, start_date, end_date):
    date_without_microseconds = date_str.split('.')[0]
    date_without_timezone = date_without_microseconds.replace('Z', '')
    date = datetime.strptime(date_without_timezone, '%Y-%m-%dT%H:%M:%S')
    end_date_inclusive = end_date + timedelta(days=1)
    return start_date <= date < end_date_inclusive

# Main function
def main():
    # File to delete
    api_csv_file = 'Alerts - Microsoft 365 security.csv'
    
    # Delete the API CSV file if it exists
    if os.path.exists(api_csv_file):
        os.remove(api_csv_file)
        print(f"Deleted file: {api_csv_file}")
    else:
        print(f"File not found, skipping deletion: {api_csv_file}")

    # Pattern for the output CSV files
    output_csv_pattern = 'MS Def Important Alerts - *.csv'

    # Find and delete files matching the pattern
    for file in glob.glob(output_csv_pattern):
        os.remove(file)
        print(f"Deleted file: {file}") 

    # Authenticate and get alerts
    token = get_access_token(tenant_id, client_id, client_secret)
    alerts_data = get_alerts(token)

    # Save the alerts data to a CSV
    save_alerts_to_csv(alerts_data)

    # Prompt for the date range
    start_date_str = input("Please enter start date (YYYY-MM-DD): ")
    end_date_str = input("Please enter end date (YYYY-MM-DD): ")

    # Convert string dates to datetime objects
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

    # Process the CSV with user input
    processed_alerts, malicious_url_count, malicious_file_count, phish_report_count, important_alerts_count = process_alerts('Alerts - Microsoft 365 security.csv', start_date, end_date)

    # Format the start and end dates for the filename
    formatted_start_date = start_date.strftime('%Y-%m-%d')
    formatted_end_date = end_date.strftime('%Y-%m-%d')
    output_filename = f"MS Def Important Alerts - {formatted_start_date}_{formatted_end_date}.csv"

    # Save the processed data to 'Cleaned Alerts.csv'
    save_to_csv(processed_alerts, output_filename)

    # Print the counts
    print(f"\nEmail messages containing malicious URL removed after delivery: {malicious_url_count}")
    print(f"Email messages containing malicious file removed after delivery: {malicious_file_count}")
    print(f"Email reported by user as malware or phish: {phish_report_count}")
    print(f"\nImportant Alerts: {important_alerts_count}")
    print(f"\nData saved to '{output_filename}' successfully!")

if __name__ == "__main__":
    main()