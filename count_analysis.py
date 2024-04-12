import sqlite3
import calendar
from datetime import datetime, timedelta

def create_connection(db_file="panorama_logs.db"):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        print(e)
    return None

def execute_query(conn, query, params=()):
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        return rows
    except sqlite3.Error as e:
        print(f"Error executing query: {e}")
        return []

def print_query_results(results, headers):
    column_widths = [len(header) for header in headers]
    for row in results:
        for i, cell in enumerate(row):
            column_widths[i] = max(column_widths[i], len(str(cell)))
    row_format = " ".join(["{:<" + str(width) + "}" for width in column_widths])
    print(row_format.format(*headers))
    for row in results:
        print(row_format.format(*row))

def validate_datetime(input_str):
    if not input_str:
        return True  # Allow blank input for optional fields
    formats = ["%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d %H", "%Y/%m/%d", "%Y/%m", "%Y"]
    for fmt in formats:
        try:
            datetime.strptime(input_str, fmt)
            return True
        except ValueError:
            continue
    return False

def get_validated_input(prompt, validation_func, default=None):
    """Get input with validation; use default if input is empty."""
    while True:
        user_input = input(prompt)
        if user_input == '':
            return default
        if validation_func(user_input):
            return user_input
        else:
            print("Invalid input, please try again.")

def get_datetime_range(start_input, end_input):
    """Calculate default start and end datetimes if not provided."""
    now = datetime.now()

    def parse_datetime(input_str):
        try:
            # Direct full datetime input
            if ':' in input_str:
                parts = input_str.split(':')
                if len(parts) == 3:  # Hours, Minutes, and Seconds specified
                    return datetime.strptime(input_str, "%Y/%m/%d %H:%M:%S"), datetime.strptime(input_str, "%Y/%m/%d %H:%M:%S") + timedelta(seconds=59)
                elif len(parts) == 2:  # Only Hours and Minutes specified
                    dt = datetime.strptime(input_str, "%Y/%m/%d %H:%M")
                    return dt, dt + timedelta(minutes=1) - timedelta(seconds=1)
                elif len(parts) == 1:  # Only Hour specified
                    dt = datetime.strptime(input_str, "%Y/%m/%d %H")
                    return dt, dt + timedelta(hours=1) - timedelta(seconds=1)

            # Date-based input processing
            parts = input_str.split('/')
            if len(parts) == 1:  # Year only
                dt = datetime(int(parts[0]), 1, 1)
                return dt, datetime(dt.year + 1, 1, 1) - timedelta(seconds=1)
            elif len(parts) == 2:  # Year and month only
                dt = datetime(int(parts[0]), int(parts[1]), 1)
                next_month = dt.month + 1 if dt.month < 12 else 1
                next_year = dt.year if next_month > 1 else dt.year + 1
                return dt, datetime(next_year, next_month, 1) - timedelta(seconds=1)
            elif len(parts) == 3:  # Full date without time
                dt = datetime.strptime(input_str, "%Y/%m/%d")
                return dt, dt + timedelta(days=1) - timedelta(seconds=1)
        except ValueError:
            return None, None

    start_datetime, end_datetime = (now - timedelta(days=1), now) if not start_input else parse_datetime(start_input)
    if end_input:
        _, end_datetime = parse_datetime(end_input)

    return start_datetime, end_datetime

def build_conditions(start_datetime, end_datetime):
    conditions = ["Time_Generated >= ?", "Time_Generated <= ?"]
    params = [start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")]
    condition_str = " AND ".join(conditions)
    return condition_str, params

def fetch_event_sequence(conn, start_datetime, end_datetime):
    """Fetch events of interest within specified date/time range for sequence analysis."""
    conditions, params = build_conditions(start_datetime, end_datetime)
    query = f"""
    SELECT IP_Address, Event_ID, Status, Time_Generated
    FROM GlobalProtectLogs
    WHERE Event_ID IN ('portal-auth', 'gateway-auth')
    {'AND ' + conditions if conditions else ''}
    ORDER BY IP_Address, Time_Generated ASC;
    """
    return execute_query(conn, query, params)

def analyze_event_sequences(events):
    """Analyze sequences of events to find specific patterns of behavior."""
    alerts = []
    last_event = {}

    for event in events:
        ip, eventid, status, time_generated = event
        if ip not in last_event:
            last_event[ip] = (eventid, status, time_generated)
            continue

        if last_event[ip][0] == 'portal-auth' and last_event[ip][1] == 'failure' and eventid == 'gateway-auth' and status == 'success':
            alerts.append((ip, last_event[ip][2], time_generated))

        last_event[ip] = (eventid, status, time_generated)

    return alerts

def print_daily_status_summary(conn, start_datetime, end_datetime):
    query = """
    SELECT strftime('%Y-%m-%d', datetime(substr(Time_Generated, 1, 4) || '-' || 
                                          substr(Time_Generated, 6, 2) || '-' || 
                                          substr(Time_Generated, 9, 2) || ' ' || 
                                          substr(Time_Generated, 12))) AS Date, 
           Status, COUNT(*) AS Count
    FROM GlobalProtectLogs
    WHERE datetime(substr(Time_Generated, 1, 4) || '-' || 
                  substr(Time_Generated, 6, 2) || '-' || 
                  substr(Time_Generated, 9, 2) || ' ' || 
                  substr(Time_Generated, 12)) >= datetime(?)
    AND datetime(substr(Time_Generated, 1, 4) || '-' || 
                substr(Time_Generated, 6, 2) || '-' || 
                substr(Time_Generated, 9, 2) || ' ' || 
                substr(Time_Generated, 12)) <= datetime(?)
    GROUP BY Date, Status
    ORDER BY Date, Status DESC;
    """
    params = [start_datetime.strftime("%Y-%m-%d %H:%M:%S"), end_datetime.strftime("%Y-%m-%d %H:%M:%S")]
    results = execute_query(conn, query, params)
    print("\nDaily Status Summary:")
    if not results:
        print("No data available for the specified range.")
        return

    current_date = ''
    for result in results:
        date, status, count = result
        if date != current_date:
            if current_date != '':
                print("")  # Print a newline for separation between days
            print(f"Date: {date}")
            current_date = date
        print(f"  {status.capitalize()} count: {count}")


def main():
    conn = create_connection("panorama_logs.db")
    if conn:
        now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y/%m/%d %H:%M:%S")
        start_datetime_input = get_validated_input('Enter start date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, yesterday)
        end_datetime_input = get_validated_input('Enter end date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, now)
        
        start_datetime, end_datetime = get_datetime_range(start_datetime_input, end_datetime_input)
        conditions, params = build_conditions(start_datetime, end_datetime)

        events = fetch_event_sequence(conn, start_datetime, end_datetime)
        alerts = analyze_event_sequences(events)
        
        if alerts:
            print("\nHeads-up! Found IPs with a failed 'portal-auth' followed by a successful 'gateway-auth':")
            for alert in alerts:
                print(f"IP: {alert[0]}, Failed portal-auth at {alert[1]}, Successful gateway-auth at {alert[2]}")
        else:
            print("\nNo instances found of an IP with a failed 'portal-auth' followed by a successful 'gateway-auth'.")

        # Ensure conditions are applied correctly in each query
        where_clause = f"WHERE {conditions}" if conditions else ""
        and_or_where = "AND" if conditions else "WHERE"

        # Define and execute other queries considering date/time filters
        queries = [
            (f"""
             SELECT IP_Address, Source_Region, COUNT(DISTINCT Source_User) AS UniqueUsernames
             FROM GlobalProtectLogs
             {where_clause}
             GROUP BY IP_Address
             ORDER BY UniqueUsernames DESC
             LIMIT 10;
             """, params, ["IP Address", "Region", "Unique Usernames"], "Top 10 IP address/username combo attempts"),

            (f"""
            SELECT IP_Address, Source_Region, COUNT(*) AS FailedAttempts
            FROM GlobalProtectLogs
            {where_clause} {and_or_where} Status = 'failure'
            GROUP BY IP_Address
            ORDER BY FailedAttempts DESC
            LIMIT 10;
            """, params, ["IP Address", "Region", "Failed Attempts"], "Top 10 IP addresses by failed login attempts"),

            (f"""
             SELECT IP_Address, Source_Region, COUNT(*) AS TotalEntries
             FROM GlobalProtectLogs
             {where_clause}
             GROUP BY IP_Address
             ORDER BY TotalEntries DESC
             LIMIT 10;
             """, params, ["IP Address", "Region", "Total Entries"], "Top 10 IP addresses by total number of log entries"),

            (f"""
             SELECT Status, COUNT(*) AS Count
             FROM GlobalProtectLogs
             {where_clause}
             GROUP BY Status
             ORDER BY Status DESC;
             """, params, ["Status", "Count"], "Total number of successes and failures"),
        ]

        for query, params, headers, description in queries:
            print(f"\n{description}:\n")
            results = execute_query(conn, query, params)
            if results:
                print_query_results(results, headers)
            else:
                print("No results found.")

        print_daily_status_summary(conn, start_datetime, end_datetime)

        conn.close()
    else:
        print("Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()