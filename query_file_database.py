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
    SELECT '{}', Time_Generated, COUNT(*) FROM {} WHERE (IP_Address = ? OR {} = ?)
    """
    additional_date_filter = "AND Time_Generated BETWEEN ? AND ? "
    group_by = "GROUP BY Time_Generated "
    params = [item, item]

    # Applying date filter if both dates are provided
    if start_date and end_date:
        base_query += additional_date_filter
        params += [start_date + " 00:00:00", end_date + " 23:59:59"]

    # Adding grouping to collate entries by timestamp
    base_query += group_by

    # Composing final query with UNION ALL
    query = (base_query.format('ThreatLogs', 'ThreatLogs', 'Destination_IP') +
             "UNION ALL " +
             base_query.format('GlobalProtectLogs', 'GlobalProtectLogs', 'Source_User'))

    cursor = conn.cursor()
    cursor.execute(query, params * 2)  # Since the same parameters are used twice
    results = cursor.fetchall()
    return results

def is_ip_address(item):
    """Check if the given item is a valid IP address."""
    try:
        ipaddress.ip_address(item)
        return True
    except ValueError:
        return False

def write_to_csv(ips, usernames):
    """Write the unique IPs and usernames to a CSV file."""
    with open('unique_ips_usernames.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Type', 'Value'])
        for ip in ips:
            writer.writerow(['IP', ip])
        for username in usernames:
            writer.writerow(['Username', username])

def read_and_search(filename, db_path, start_date=None, end_date=None):
    """Read the file, search each item in the database within the date range, and display results."""
    conn = create_connection(db_path)
    if conn:
        with open(filename, 'r') as file:
            items = file.read().splitlines()

        total_occurrences = 0
        found = False
        unique_usernames = set()
        unique_ips = set()  # To track unique IP addresses
        for item in items:
            if is_ip_address(item):  # Treat valid IP items as IPs
                unique_ips.add(item)
            else:  # Assume anything else is a username
                unique_usernames.add(item)
            results = query_database(conn, item, start_date, end_date)
            for result in results:
                table_name, time_generated, count = result
                if count > 0:
                    found = True
                    total_occurrences += count
                    print(f'Found {count} occurrences for {item} in {table_name} at {time_generated}')

        if found:
            print("\nTotal number of occurrences found:", total_occurrences)
            print("Total number of unique usernames found:", len(unique_usernames))
            print("Total number of unique IP addresses found:", len(unique_ips))
            write_to_csv(unique_ips, unique_usernames) 
            print("\nUnique IPs and usernames have been written to 'unique_ips_usernames.csv'.")
        else:
            print("No occurrences found for any entries.")
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