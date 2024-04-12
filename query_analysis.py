import sqlite3
import os
from datetime import datetime, timedelta

def create_connection(db_file="panorama_logs.db"):
    """Create a database connection to the SQLite database specified by db_file."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, db_file)
        conn = sqlite3.connect(db_path)
        return conn
    except sqlite3.Error as e:
        print(e)
    return None

def execute_query(conn, query, params):
    """Execute SQL query and return the results."""
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        return rows
    except sqlite3.Error as e:
        print(f"Error executing query: {e}")
        return []

def get_user_input(prompt):
    """Prompt the user for input and return it."""
    return input(prompt)

def get_validated_input(prompt, validation_func):
    """Prompt the user for input until it passes validation."""
    while True:
        user_input = input(prompt)
        if validation_func(user_input):
            return user_input
        else:
            print("Invalid input, please try again.")

def validate_date(input_date):
    """Validate the date input."""
    if input_date == '':
        return True  # Allow blank input for optional fields
    try:
        if len(input_date.split('/')) == 3:
            datetime.strptime(input_date, "%Y/%m/%d")
        elif len(input_date.split('/')) == 2:
            datetime.strptime(input_date, "%Y/%m")
        else:
            datetime.strptime(input_date, "%Y")
        return True
    except ValueError:
        return False

def validate_time(input_time):
    """Validate the time input."""
    if input_time == '':
        return True  # Allow blank input for optional fields
    try:
        datetime.strptime(input_time, "%H:%M:%S")
        return True
    except ValueError:
        if len(input_time.split(':')) in [2, 1]:
            try:
                datetime.strptime(input_time, "%H:%M")
                return True
            except ValueError:
                try:
                    datetime.strptime(input_time, "%H")
                    return True
                except ValueError:
                    return False
        return False

def build_query(log_type):
    conditions = []
    params = []

    # Shared date and time inputs with defaults when blank
    date_input = get_validated_input('Enter date (YYYY/MM/DD), or leave blank for the last day: ', validate_date)
    time_input = get_validated_input('Enter time (HH:MM:SS), or leave blank for the whole day: ', validate_time)

    # Default to the last day's data if no date input is provided
    if not date_input:
        now = datetime.now()
        start_datetime = now - timedelta(days=1)
        end_datetime = now
        date_input = start_datetime.strftime("%Y/%m/%d")  # This line is optional, just for debugging purposes
    else:
        date_parts = date_input.split('/')
        if len(date_parts) == 1:
            start_datetime = datetime.strptime(date_input, "%Y")
            end_datetime = start_datetime.replace(year=start_datetime.year + 1) - timedelta(seconds=1)
        elif len(date_parts) == 2:
            start_datetime = datetime.strptime(date_input, "%Y/%m")
            if start_datetime.month == 12:
                end_datetime = start_datetime.replace(year=start_datetime.year + 1, month=1) - timedelta(seconds=1)
            else:
                end_datetime = start_datetime.replace(month=start_datetime.month + 1) - timedelta(seconds=1)
        else:
            start_datetime = datetime.strptime(date_input, "%Y/%m/%d")
            end_datetime = start_datetime + timedelta(days=1) - timedelta(seconds=1)

    if not time_input:
        conditions.append("Time_Generated >= ? AND Time_Generated < ?")
        params.extend([start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")])
    else:
        time_parts = time_input.split(':')
        if len(time_parts) == 1:
            start_datetime = datetime.combine(start_datetime.date(), datetime.strptime(time_input, "%H").time())
            end_datetime = start_datetime + timedelta(hours=1) - timedelta(seconds=1)
        elif len(time_parts) == 2:
            start_datetime = datetime.combine(start_datetime.date(), datetime.strptime(time_input, "%H:%M").time())
            end_datetime = start_datetime + timedelta(minutes=1) - timedelta(seconds=1)
        else:
            start_datetime = datetime.combine(start_datetime.date(), datetime.strptime(time_input, "%H:%M:%S").time())
            end_datetime = start_datetime + timedelta(seconds=1) - timedelta(microseconds=1)
        conditions.append("Time_Generated >= ? AND Time_Generated < ?")
        params.extend([start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")])

    if log_type == 'globalprotect':
        fields = ['IP address', 'username', 'country', 'portal', 'event ID', 'status']
        db_columns = ['IP_Address', 'Source_User', 'Source_Region', 'Portal', 'eventid', 'Status']
        for field, column in zip(fields, db_columns):
            user_input = get_user_input(f'Enter {field}, or leave blank: ')
            if user_input:
                if column == 'Source_User':
                    conditions.append(f"UPPER({column}) LIKE UPPER(?)")
                    params.append(f"%{user_input}%")
                else:
                    conditions.append(f"{column} = ?")
                    params.append(user_input)
        base_query = "SELECT * FROM GlobalProtectLogs"
    elif log_type == 'threat':
        fields = ['IP address', 'destination IP', 'source region', 'destination region', 'action', 'threat ID', 'severity']
        db_columns = ['IP_Address', 'Destination_IP', 'Source_Region', 'Destination_Region', 'Action', 'Threat_ID', 'Severity']
        for field, column in zip(fields, db_columns):
            user_input = get_user_input(f'Enter {field}, or leave blank: ')
            if user_input:
                conditions.append(f"{column} = ?")
                params.append(user_input)
        base_query = "SELECT * FROM ThreatLogs"

    if conditions:
        base_query = f"SELECT * FROM {log_type}Logs WHERE " + " AND ".join(conditions)
    else:
        base_query = f"SELECT * FROM {log_type}Logs"  # Default query if no conditions are met

    return base_query, params

def main():
    conn = create_connection()
    if not conn:
        print("Error! Cannot create the database connection.")
        return

    while True:
        log_type = get_user_input("Enter log type ('GlobalProtect' or 'Threat'): ").strip().lower()
        if log_type not in ['globalprotect', 'threat']:
            print("Invalid log type. Please enter 'GlobalProtect' or 'Threat'.")
            continue

        query, params = build_query(log_type)

        print("\nQuerying database...\n")
        results = execute_query(conn, query, params)
        if results:
            for row in results:
                print(row)
        else:
            print("No results found.")

        print(f"\nNumber of results returned: {len(results)}\n")  # Print the count of results

        if get_user_input("Query another log type? (yes/no): ").strip().lower() != 'yes':
            break

    conn.close()

if __name__ == '__main__':
    main()
