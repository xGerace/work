from datetime import datetime, timedelta
from module_database import execute_query
from module_utility import build_conditions

def fetch_event_sequence(conn, start_datetime, end_datetime):
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

def print_query_results(results, headers):
    column_widths = [len(header) for header in headers]
    for row in results:
        for i, cell in enumerate(row):
            column_widths[i] = max(column_widths[i], len(str(cell)))
    row_format = " ".join(["{:<" + str(width) + "}" for width in column_widths])
    print(row_format.format(*headers))
    for row in results:
        print(row_format.format(*row))

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
    
    summary = "\nDaily Status Summary:\n"
    if not results:
        summary += "No data available for the specified range."
        return summary

    current_date = ''
    for result in results:
        date, status, count = result
        if date != current_date:
            if current_date != '':
                summary += "\n"  # Print a newline for separation between days
            summary += f"Date: {date}\n"
            current_date = date
        summary += f"  {status.capitalize()} count: {count}\n"
    return summary