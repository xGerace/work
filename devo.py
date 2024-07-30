import requests
import os
from dotenv import load_dotenv
import csv
from datetime import datetime, timedelta
import time
from collections import Counter

load_dotenv()

# Convert date to epoch time in milliseconds
def date_to_epoch(date_string, is_end=False):
    date_format = "%Y-%m-%d" 
    if is_end:
        # Adjust to include the entire end day by moving to the last second of the day
        adjusted_date = datetime.strptime(date_string, date_format) + timedelta(days=1, seconds=-1)
        epoch = int(time.mktime(adjusted_date.timetuple())) * 1000
    else:
        epoch = int(time.mktime(time.strptime(date_string, date_format))) * 1000
    return epoch

def fetch_alerts(start_epoch, end_epoch):
    url = "https://api-us.devo.com/alerts/v1/alerts/list"
    headers = {
        'standAloneToken': os.getenv('DEVO_API_TOKEN')
    }

    params = {
        'limit': 1000,
        'offset': 0,
        'from': start_epoch,
        'to': end_epoch
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch alerts: {response.status_code}, {response.text}")

def convert_epoch_to_readable(epoch_time):
    return datetime.fromtimestamp(epoch_time / 1000).strftime('%Y-%m-%d %H:%M:%S')

def main():
    start_date = input("Enter the start date (YYYY-MM-DD): ")
    end_date = input("Enter the end date (YYYY-MM-DD): ")

    start_epoch = date_to_epoch(start_date)
    end_epoch = date_to_epoch(end_date, is_end=True)

    try:
        alerts = fetch_alerts(start_epoch, end_epoch)
        print(f"\nFetched {len(alerts)} alerts.")

        # Filter out alerts with no createDate
        valid_alerts = [alert for alert in alerts if alert.get('createDate') is not None]

        if valid_alerts:
            # Find the earliest and latest createDate in the alerts
            earliest_date = min(alert['createDate'] for alert in valid_alerts)
            latest_date = max(alert['createDate'] for alert in valid_alerts)

            earliest_date_readable = convert_epoch_to_readable(int(earliest_date))
            latest_date_readable = convert_epoch_to_readable(int(latest_date))

            print(f"\nEarliest alert creation date: {earliest_date_readable}")
            print(f"Latest alert creation date: {latest_date_readable}")

            with open('alerts.csv', mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(valid_alerts[0].keys())
                for alert in valid_alerts:
                    writer.writerow(alert.values())

            print("\nAlerts written to 'alerts.csv'.")

            context_counts = Counter()
            for alert in valid_alerts:
                alert_prefix = os.getenv('ALERT_PREFIX', '')  # Default to empty string if not found
                context = alert.get('context', '').replace(alert_prefix, "")
                context_counts[context] += 1

            print("\nAlert Counts by Context (sorted by count):")
            for context, count in context_counts.most_common():
                print(f"{context}: {count}")

            priority_counts = Counter()
            for alert in valid_alerts:
                priority = alert.get('alertPriority')
                if not priority:  
                    priority = 'None'
                priority_counts[priority] += 1

            priority_order = ['5', '4', '3', '2', '1', '0', 'None']

            print("\nAlert Counts by Priority:")
            for priority in priority_order:
                print(f"{priority}: {priority_counts[priority]}")

        else:
            print("No valid alerts found for the given date range.")

    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    main()