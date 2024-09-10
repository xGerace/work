import sqlite3
from datetime import datetime
import ipaddress
import csv

def create_connection(db_file):
    """Create a database connection to the specified SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(e)
    return conn

def query_database(conn, item, start_date, end_date):
    """Query the database to find occurrences of the IP address or username within a date range."""
    base_query = """
    SELECT '{}', Time_Generated, COUNT(*)
    FROM {} WHERE IP_Address = ? AND Time_Generated BETWEEN ? AND ?
    """
    params = [item, start_date + " 00:00:00", end_date + " 23:59:59"]

    query = (base_query.format('ThreatLogs', 'ThreatLogs') +
             " UNION ALL " +
             base_query.format('GlobalProtectLogs', 'GlobalProtectLogs'))

    cursor = conn.cursor()
    cursor.execute(query, params * 2)
    results = cursor.fetchall()
    return results

def is_ip_address(item):
    """Check if the given item is a valid IP address."""
    try:
        ipaddress.ip_address(item)
        return True
    except ValueError:
        return False

def write_to_csv(ip_occurrences, username_occurrences, start_date, end_date):
    """Write the unique IPs and usernames found in the database to a CSV file with their counts and log type."""
    start_date_safe = start_date.replace("/", "-")
    end_date_safe = end_date.replace("/", "-")
    
    csv_filename = f'unique_ips_usernames_{start_date_safe}_to_{end_date_safe}.csv'
    
    with open(csv_filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Type', 'Value', 'Log Type', 'Count']) 
        for ip, (count, log_type) in ip_occurrences.items():
            writer.writerow(['IP', ip, log_type, count])
        for username, (count, log_type) in username_occurrences.items():
            writer.writerow(['Username', username, log_type, count])

def read_and_search(filename, db_path, start_date=None, end_date=None):
    """Read the file, search each item in the database within the date range, and display results."""
    conn = create_connection(db_path)
    if conn:
        with open(filename, 'r') as file:
            items = file.read().splitlines()

        total_occurrences = 0
        ip_occurrences = {}  # To track occurrences of each IP and log type
        username_occurrences = {}  # To track occurrences of each username and log type

        for item in items:
            results = query_database(conn, item, start_date, end_date)
            for result in results:
                table_name, time_generated, count = result
                if count > 0:
                    if is_ip_address(item):
                        if item not in ip_occurrences:
                            ip_occurrences[item] = (0, table_name)
                        ip_occurrences[item] = (ip_occurrences[item][0] + count, table_name)
                    else:
                        if item not in username_occurrences:
                            username_occurrences[item] = (0, table_name)
                        username_occurrences[item] = (username_occurrences[item][0] + count, table_name)
                    total_occurrences += count
                    print(f'Found {count} occurrences for {item} in {table_name} at {time_generated}')

        print("\nTotal number of occurrences found:", total_occurrences)
        print("Total number of unique IP addresses found in database:", len(ip_occurrences))
        print("Total number of unique usernames found in database:", len(username_occurrences))
        write_to_csv(ip_occurrences, username_occurrences, start_date, end_date)
        print(f"\nUnique IPs and usernames found in the database with their counts have been written to 'unique_ips_usernames_{start_date}_to_{end_date}.csv'.")

        conn.close()
    else:
        print("Failed to create database connection.")

if __name__ == '__main__':
    filename = input("Enter the name of the file containing IPs/usernames: ")
    start_date = input("Enter start date (YYYY, YYYY/MM, YYYY/MM/DD), leave blank for entire database: ")
    end_date = input("Enter end date (YYYY/MM/DD), leave blank to use today's date: ")

    # Flexible date inputs
    if start_date:
        try:
            start_date = datetime.strptime(start_date, "%Y/%m/%d").strftime("%Y/%m/%d")
        except ValueError:
            try:
                start_date = datetime.strptime(start_date, "%Y/%m").strftime("%Y/%m/%d")
            except ValueError:
                try:
                    start_date = datetime.strptime(start_date, "%Y").strftime("%Y/%m/%d")
                except ValueError:
                    print("Invalid start date format. Using default to search entire database.")
                    start_date = None
    if not end_date:
        end_date = datetime.today().strftime("%Y/%m/%d")
    else:
        try:
            end_date = datetime.strptime(end_date, "%Y/%m/%d").strftime("%Y/%m/%d")
        except ValueError:
            print("Invalid end date format. Using today's date.")
            end_date = datetime.today().strftime("%Y/%m/%d")

    database_path = "./panorama_logs.db"
    read_and_search(filename, database_path, start_date, end_date)