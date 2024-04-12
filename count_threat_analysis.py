import sqlite3
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

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
        return cur.fetchall()
    except sqlite3.Error as e:
        print(f"Error executing query: {e}")
        return []

def print_query_results(results, headers):
    if not results:
        print("No results found.")
        return
    column_widths = [max(len(header), max((len(str(row[i]) if row[i] is not None else '') for row in results), default=0)) for i, header in enumerate(headers)]
    row_format = "  ".join("{:<" + str(width) + "}" for width in column_widths)
    print(row_format.format(*headers))
    for row in results:
        print(row_format.format(*(str(cell) if cell is not None else '' for cell in row)))

def get_date_input(prompt):
    user_input = input(prompt)
    if not user_input:
        return None, None
    formats = ["%Y", "%Y/%m", "%Y/%m/%d", "%Y/%m/%d %H", "%Y/%m/%d %H:%M", "%Y/%m/%d %H:%M:%S"]
    for fmt in formats:
        try:
            dt = datetime.strptime(user_input, fmt)
            if fmt == "%Y":
                return dt, datetime(dt.year + 1, 1, 1)
            if fmt == "%Y/%m":
                next_month = dt.month % 12 + 1
                next_year = dt.year + dt.month // 12
                return dt, datetime(next_year, next_month, 1)
            if fmt.endswith("d"):
                return dt, dt + timedelta(days=1)
            if fmt.endswith("H"):
                return dt, dt + timedelta(hours=1)
            if fmt.endswith("M"):
                return dt, dt + timedelta(minutes=1)
            return dt, dt + timedelta(seconds=1)
        except ValueError:
            continue
    print("Invalid date format entered. Please use formats like YYYY, YYYY/MM, YYYY/MM/DD HH:MM, etc.")
    return None, None

def get_user_confirmation(prompt):
    user_input = input(prompt).lower()
    return user_input in ['yes', 'y']

def main():
    conn = create_connection()
    if not conn:
        print("Error! Cannot create the database connection.")
        return

    start_datetime, end_datetime = get_date_input('Enter start date/time, or leave blank for the last 24 hours (use formats like YYYY, YYYY/MM, YYYY/MM/DD HH:MM, etc.): ')
    if not start_datetime:
        start_datetime = datetime.now() - timedelta(days=1)
        end_datetime = datetime.now()

    exclude_own_ips = get_user_confirmation('Do you want to exclude threats from IPs in the ' + os.getenv('ORG_IP_PREFIX') + '.*.* range? (yes/no): ')
    ip_exclusion_condition = "AND IP_Address NOT LIKE '" + os.getenv('ORG_IP_PREFIX') + ".%' " if exclude_own_ips else ""

    params = [start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")]

    # Top 10 Threat IDs by count with severity
    query_threat_ids = f"""
    SELECT Threat_ID, Severity, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY Threat_ID, Severity
    ORDER BY Count DESC
    LIMIT 10;
    """
    print("\nTop 10 Threat IDs by count with severity:")
    results = execute_query(conn, query_threat_ids, params)
    print_query_results(results, ["Threat ID", "Severity", "Count"])

    # Threat count by country
    query_country = f"""
    SELECT Source_Region AS Country, COUNT(*) AS Threats
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? 
        AND Source_Region NOT LIKE '%.%'
        AND Source_Region NOT GLOB '*[0-9]*' {ip_exclusion_condition}
    GROUP BY Source_Region
    ORDER BY Threats DESC
    LIMIT 10;
    """
    print("\nThreat count by country:")
    results = execute_query(conn, query_country, params)
    print_query_results(results, ["Country", "Threats"])

    # Top 10 IPs by threat count
    query_top_ips = f"""
    SELECT IP_Address, Source_Region, COUNT(*) AS Threat_Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? 
        AND Source_Region NOT LIKE '%.%'
        AND Source_Region NOT GLOB '*[0-9]*' {ip_exclusion_condition}
    GROUP BY IP_Address, Source_Region
    ORDER BY Threat_Count DESC 
    LIMIT 10; 
    """
    print("\nTop 10 IP addresses by threat count:")
    results = execute_query(conn, query_top_ips, params)
    print_query_results(results, ["IP Address", "Source Region", "Threat Count"])

    # Breakdown of threats by severity
    query_severity = f"""
    SELECT Severity, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY Severity
    ORDER BY CASE Severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'informational' THEN 5
        ELSE 6
    END;
    """
    print("\nBreakdown of threats by severity:")
    results = execute_query(conn, query_severity, params)
    print_query_results(results, ["Severity", "Count"])

    # Daily count of threats
    query_daily = f"""
    SELECT strftime('%Y-%m-%d', replace(Time_Generated, '/', '-')) AS Date, COUNT(*) AS Daily_Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY strftime('%Y-%m-%d', replace(Time_Generated, '/', '-'))
    ORDER BY Date DESC;
    """
    print("\nDaily count of threats:")
    results = execute_query(conn, query_daily, params)
    print_query_results(results, ["Date", "Daily Count"])

    # Query to count each type of Action within the threat data
    query_actions = f"""
    SELECT Action, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY Action
    ORDER BY Count DESC;
    """
    print("\nCount of each type of Action:")
    results = execute_query(conn, query_actions, params)
    print_query_results(results, ["Action", "Count"])

    conn.close()

if __name__ == '__main__':
    main()
