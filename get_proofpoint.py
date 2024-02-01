import os
import requests
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Common Variables
api_key = os.getenv('PROOFPOINT_API_KEY')
api_secret = os.getenv('PROOFPOINT_API_SECRET')
base_url = "https://tap-api-v2.proofpoint.com"

# API Call Function
def make_api_call(endpoint, params=None):
    full_url = f"{base_url}{endpoint}"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(full_url, headers=headers, params=params, auth=(api_key, api_secret))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        return {'error': f'HTTP Error: {err}'}
    except Exception as err:
        return {'error': f'Error: {err}'}

# Function to fetch VAP data
def fetch_vap_data(window, size=1000, page=1):
    endpoint = '/v2/people/vap'
    params = {'window': window, 'size': size, 'page': page}
    return make_api_call(endpoint, params)

# Function to fetch Top Clickers data
def fetch_top_clickers_data(window, size=100):
    endpoint = '/v2/people/top-clickers'
    params = {'window': window, 'size': size}
    return make_api_call(endpoint, params)

# Function to print and sort list based on specified attributes
def print_and_sort_list(data, list_type, sort_attribute):
    people = {}
    for person in data.get('users', []):
        identity = person.get('identity', {})
        emails = identity.get('emails', [])
        vip_status = identity.get('vip', False)  # Fetch VIP status

        if list_type == 'vap':
            attack_index = person.get('threatStatistics', {}).get('attackIndex', 0)
            value = (vip_status, attack_index)
        else:  # top-clickers
            click_count = person.get('clickStatistics', {}).get('clickCount', 0)
            value = (vip_status, click_count)  # Include VIP status in the value

        for email in emails:
            if '@students' not in email:
                if email in people:
                    current_vip_status, current_count = people[email]
                    people[email] = (current_vip_status, current_count + value[1])
                else:
                    people[email] = value

    sorted_people = sorted(people.items(), key=lambda x: x[1][1], reverse=True)

    if list_type == 'vap':
        print("Very Attacked People:")
    else:  # top-clickers
        print("Top Clickers:")

    for email, (vip, count) in sorted_people:
        vip_status = 'Yes' if vip else 'No'
        print(f"{email}, VIP: {vip_status}, {'Attack Index' if list_type == 'vap' else 'Click Count'}: {count}")

    return len(sorted_people)

# Function to get forensic data for a specific campaign
def get_forensic_data(campaign_id):
    endpoint = f'/v2/forensics?campaignId={campaign_id}'
    return make_api_call(endpoint)

# Function to get campaign IDs for a specific date
def get_campaign_ids(date):
    endpoint = f'/v2/campaign/ids?interval={date}T00:00:00Z/{date}T23:59:59Z&page=1&size=100'
    return make_api_call(endpoint)

# Function to get details of a specific campaign
def get_campaign_details(campaign_id):
    endpoint = f'/v2/campaign/{campaign_id}'
    return make_api_call(endpoint)

# Function to format date interval
def format_interval(interval):
    start_date_str, end_date_str = interval.split('/')
    start_date = datetime.fromisoformat(start_date_str.replace("Z", "+00:00"))
    end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
    return f"{start_date.strftime('%B %d, %Y %H:%M:%S')} to {end_date.strftime('%B %d, %Y %H:%M:%S')}"

# Function to filter members by threat time and status
def filter_members(members, start_date, end_date):
    filtered_members = []
    member_types_count = {}
    for member in members:
        threat_time = datetime.strptime(member['threatTime'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if start_date <= threat_time <= end_date and member['threatStatus'] != 'cleared':
            filtered_members.append(member)
            member_type = member['type']
            member_types_count[member_type] = member_types_count.get(member_type, 0) + 1
    return filtered_members, member_types_count

# Function to fetch campaign data for a date range
def fetch_campaign_data(start_date, end_date):
    # Check if file exists and delete if it does
    if os.path.exists('detailed_campaign_data.json'):
        os.remove('detailed_campaign_data.json')
        print(f"\nExisting file 'detailed_campaign_data.json' found and deleted.")

    detailed_campaign_data = []
    campaign_ids_collected = set()
    overall_member_types_count = {}

    current_date = start_date
    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        campaign_ids_response = get_campaign_ids(date_str)

        if 'campaigns' in campaign_ids_response:
            for campaign in campaign_ids_response['campaigns']:
                if campaign['id'] not in campaign_ids_collected:
                    campaign_ids_collected.add(campaign['id'])
                    campaign_detail_response = get_campaign_details(campaign['id'])
                    forensic_data_response = get_forensic_data(campaign['id'])
                    if 'error' not in campaign_detail_response and 'error' not in forensic_data_response:
                        members = campaign_detail_response.get('campaignMembers', [])
                        filtered_members, member_types_count = filter_members(members, start_date, end_date)
                        for member_type, count in member_types_count.items():
                            overall_member_types_count[member_type] = overall_member_types_count.get(member_type, 0) + count
                        campaign_info = {
                            'campaign_id': campaign['id'],
                            'name': campaign_detail_response.get('name', ''),
                            'description': campaign_detail_response.get('description', ''),
                            'startDate': campaign_detail_response.get('startDate', ''),
                            'notable': campaign_detail_response.get('notable', False),
                            'members': filtered_members,
                            'forensic_data': forensic_data_response
                        }
                        detailed_campaign_data.append(campaign_info)

        current_date += timedelta(days=1)

    # Write detailed campaign data to a file
    with open('detailed_campaign_data.json', 'w') as file:
        json.dump(detailed_campaign_data, file, indent=4)

    # Print the results
    print(f"\nTotal number of campaigns within date range: {len(detailed_campaign_data)}")
    print(f"Total number of campaign members within date range: {sum(len(c['members']) for c in detailed_campaign_data)}")
    print(f"\nCounts of each member type:")
    for member_type, count in overall_member_types_count.items():
        print(f"{member_type}: {count}")

# Function to save data to a file
def save_data_to_file(data, filename):
    if os.path.exists(filename):
        os.remove(filename)
        print(f"\nExisting file {filename} was found and deleted.\n")
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

# Main function to execute the script
def main():
    # For Campaign data
    start_date_str = input("Enter the start date for campaign data (YYYY-MM-DD): ")
    end_date_str = input("Enter the end date for campaign data (YYYY-MM-DD): ")
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
    fetch_campaign_data(start_date, end_date)

    # For People data (VAP and Top Clickers)
    window = 14  # Past 14 days
    vap_data = fetch_vap_data(window)
    save_data_to_file(vap_data, 'vap_data.json')
    vap_count = print_and_sort_list(vap_data, 'vap', 'attackIndex')
    print(f"\nTotal Very Attacked People: {vap_count}")
    if 'interval' in vap_data:
        formatted_vap_interval = format_interval(vap_data['interval'])
        print(f"VAP Date Interval: {formatted_vap_interval}")

    top_clickers_data = fetch_top_clickers_data(window)
    save_data_to_file(top_clickers_data, 'top_clickers_data.json')
    top_clickers_count = print_and_sort_list(top_clickers_data, 'top-clickers', 'clickCount')
    print(f"\nTotal Top Clickers: {top_clickers_count}")
    if 'interval' in top_clickers_data:
        formatted_clickers_interval = format_interval(top_clickers_data['interval'])
        print(f"Top Clickers Date Interval: {formatted_clickers_interval}")

    print(f"\nData fetched and saved successfully.")

# Run the script
if __name__ == "__main__":
    main()
