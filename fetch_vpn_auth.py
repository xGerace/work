import requests
from urllib.parse import quote
import time
import os
import csv
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Use environment variables
PANORAMA_HOST = os.getenv('PANORAMA_ENDPOINT')
API_KEY = os.getenv('PANORAMA_API_KEY')
LOG_TYPE = 'globalprotect'
LOG_NUM = 5000  # Specify the number of logs to retrieve for each request

# Function to initiate the log query job
def initiate_log_query(start_time, end_time):
    query_url = f"https://{PANORAMA_HOST}/api/?type=log&log-type={LOG_TYPE}&key={quote(API_KEY)}&query=(time_generated geq '{start_time}') and (time_generated leq '{end_time}')&nlogs={LOG_NUM}"
    response = requests.get(query_url, verify=True)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        job_id = root.find('.//job').text
        return job_id
    else:
        print(f"Failed to initiate log query: {response.status_code}, Response: {response.text}")
        return None

# Function to check the job status
def check_job_status(job_id):
    status_url = f"https://{PANORAMA_HOST}/api/?type=log&action=get&job-id={job_id}&key={quote(API_KEY)}"
    print("Checking job status...")
    while True:
        response = requests.get(status_url, verify=True)
        if response.status_code == 200 and 'success' in response.text:
            print("Job completed, fetching logs...")
            return True
        else:
            print("Job still processing. Waiting...")
            time.sleep(10)  # Wait for 10 seconds before checking again

# Function to fetch and process the logs
def fetch_and_process_logs(job_id, is_first):
    logs_url = f"https://{PANORAMA_HOST}/api/?type=log&action=get&job-id={job_id}&key={quote(API_KEY)}"
    response = requests.get(logs_url, verify=True)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        entries = root.findall('.//entry')
        with open('vpn_logs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            if is_first:  # Write header only for the first batch
                writer.writerow(['Time Generated', 'Public IP', 'Source Region', 'Source User', 'Portal', 'Event ID', 'Status'])
            for entry in entries:
                raw_src_user = entry.find('srcuser').text if entry.find('srcuser') is not None else ""
                # Normalize srcuser by checking for empty or whitespace-only strings
                if not raw_src_user.strip(): 
                    src_user = "N/A"
                else:
                    # Remove domain prefixes and trim, if the username is not empty
                    src_user = raw_src_user.split('\\')[-1].strip().lower()
                
                writer.writerow([
                    entry.find('time_generated').text.strip().lower() if entry.find('time_generated') is not None else "N/A",
                    entry.find('public_ip').text.strip().lower() if entry.find('public_ip') is not None else "N/A",
                    entry.find('srcregion').text.strip() if entry.find('srcregion') is not None else "N/A",
                    src_user,
                    entry.find('portal').text.strip().lower() if entry.find('portal') is not None else "N/A",
                    entry.find('eventid').text.strip().lower() if entry.find('eventid') is not None else "N/A",
                    entry.find('status').text.strip().lower() if entry.find('status') is not None else "N/A"
                ])

# Main execution logic for fetching logs of the specified day
specified_day = input("Enter the day you want to fetch logs for (YYYY/MM/DD): ")
start_day = datetime.strptime(specified_day, '%Y/%m/%d')
end_day = start_day + timedelta(days=1)

# Check if the file exists before starting to write data
csv_file_path = 'vpn_logs.csv'
if os.path.exists(csv_file_path):
    os.remove(csv_file_path)  # Delete the file if it exists
    print(f"Found and deleted existing file: {csv_file_path}\n")

is_first_batch = True
for hour in range(24):
    start_time = start_day + timedelta(hours=hour)
    end_time = start_day + timedelta(hours=hour+1)
    formatted_start_time = start_time.strftime('%Y/%m/%d %H:%M:%S')
    formatted_end_time = end_time.strftime('%Y/%m/%d %H:%M:%S')
    print(f"Fetching logs from {formatted_start_time} to {formatted_end_time}...")

    job_id = initiate_log_query(formatted_start_time, formatted_end_time)
    if job_id and check_job_status(job_id):
        fetch_and_process_logs(job_id, is_first_batch)
        is_first_batch = False
    else:
        print(f"Failed to initiate or check the job status for the time range from {formatted_start_time} to {formatted_end_time}.")

print(f"\nCompleted fetching logs for the entire day.")

def analyze_logs():
    # Initialize counters and mappings
    ip_counter = Counter()
    user_ip_combo_counter = Counter()
    ip_region_mapping = {}
    user_ip_region_mapping = {}  # Track the latest non-"N/A" region for each user+IP combo
    ip_usernames_mapping = defaultdict(set)  # Tracks unique usernames attempted by each IP
    success_counter = Counter()
    failure_counter = Counter()

    with open('vpn_logs.csv', mode='r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            ip = row['Public IP']
            user = row['Source User']
            region = row['Source Region']
            status = row['Status']
            
            # Update IP counter and region mapping
            ip_counter[ip] += 1
            if region != "N/A":
                ip_region_mapping[ip] = region
            
            # Number of success or failure in Status column
            if status == "success":
                success_counter[ip] += 1
            elif status == "failure":
                failure_counter[ip] += 1

            # Handle user+IP combo for counting attempts
            if user != "N/A" and ip != "N/A":
                user_ip_combo = f"{user}||{ip}"
                user_ip_combo_counter[user_ip_combo] += 1
                ip_usernames_mapping[ip].add(user)  # Add user to set of unique usernames for the IP
                
                # Update user+IP region mapping if the current region is not "N/A"
                if region != "N/A":
                    user_ip_region_mapping[user_ip_combo] = region

    # Calculate counts of unique usernames for each IP
    unique_usernames_count = {ip: len(usernames) for ip, usernames in ip_usernames_mapping.items()}
    
    # Sort IPs by the number of unique usernames attempted
    top_ips_by_unique_usernames = sorted(unique_usernames_count.items(), key=lambda x: x[1], reverse=True)[:10]

    # Display top 10 IPs by count
    print("\nTop 10 IPs by Count:")
    for ip, count in ip_counter.most_common(10):
        region = ip_region_mapping.get(ip, "N/A")
        print(f"IP: {ip}, Region: {region}, Count: {count}")

    # Display top 10 User+IP Combos by count
    print("\nTop 10 User+IP Combos by Count:")
    for user_ip_combo, count in user_ip_combo_counter.most_common(10):
        user, ip = user_ip_combo.split("||")
        # Use the most recently seen non-"N/A" region for this user+IP combo, if available
        region = user_ip_region_mapping.get(user_ip_combo, "N/A")
        print(f"User: {user}, IP: {ip}, Region: {region}, Count: {count}")

    # Display top 10 IPs by Unique Usernames Attempted
    print("\nTop 10 IPs by Unique Usernames Attempted:")
    for ip, count in top_ips_by_unique_usernames:
        region = ip_region_mapping.get(ip, "N/A")
        print(f"IP: {ip}, Region: {region}, Unique Usernames: {count}")

    total_successes = sum(success_counter.values())
    total_failures = sum(failure_counter.values())
    print(f"\nTotal Successful Logins: {total_successes}")
    print(f"Total Failed Logins: {total_failures}")

analyze_logs()