import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key and API secret from .env file
api_key = os.getenv('PROOFPOINT_API_KEY')
api_secret = os.getenv('PROOFPOINT_API_SECRET')

# Base URL for the People API
base_url = "https://tap-api-v2.proofpoint.com/v2/people"

# Function to make API calls
def make_api_call(endpoint, params):
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
    endpoint = '/vap'
    params = {'window': window, 'size': size, 'page': page}
    return make_api_call(endpoint, params)

# Function to fetch Top Clickers data
def fetch_top_clickers_data(window, size=100):
    endpoint = '/top-clickers'
    params = {'window': window, 'size': size}
    return make_api_call(endpoint, params)

# Function to print and sort list based on a specified attribute
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

# Function to save data to a file
def save_data_to_file(data, filename):
    if os.path.exists(filename):
        os.remove(filename)
        print(f"\nThe file {filename} was deleted successfully.\n")
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

# Function to format date interval
def format_interval(interval):
    start_date_str, end_date_str = interval.split('/')
    start_date = datetime.fromisoformat(start_date_str.replace("Z", "+00:00"))
    end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
    return f"{start_date.strftime('%B %d, %Y %H:%M:%S')} to {end_date.strftime('%B %d, %Y %H:%M:%S')}"

# Main function to execute the script
def main():
    window = 14  # Hard-coded to retrieve data for the past 14 days

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

    print("Data fetched and saved successfully.")

# Run the script
main()
