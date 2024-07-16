import sqlite3
from module_database import create_connection

def query_database_for_offenders(conn, item, start_date, end_date):
    """Query the database to find the first and last occurrences of the IP address or username within a date range."""
    queries = [
        {
            "query": """
            SELECT 'ThreatLogs', MIN(Time_Generated), MAX(Time_Generated), COUNT(*), GROUP_CONCAT(DISTINCT IP_Address), GROUP_CONCAT(DISTINCT Destination_IP), GROUP_CONCAT(DISTINCT Source_Region)
            FROM ThreatLogs WHERE (IP_Address = ? OR Destination_IP = ?)
            AND Time_Generated BETWEEN ? AND ?
            """,
            "params": [item, item, start_date + " 00:00:00", end_date + " 23:59:59"]
        },
        {
            "query": """
            SELECT 'GlobalProtectLogs', MIN(Time_Generated), MAX(Time_Generated), COUNT(*), GROUP_CONCAT(DISTINCT IP_Address), GROUP_CONCAT(DISTINCT Source_User), GROUP_CONCAT(DISTINCT Source_Region)
            FROM GlobalProtectLogs WHERE (IP_Address = ? OR Source_User = ?)
            AND Time_Generated BETWEEN ? AND ?
            """,
            "params": [item, item, start_date + " 00:00:00", end_date + " 23:59:59"]
        }
    ]

    results = []
    cursor = conn.cursor()
    for q in queries:
        cursor.execute(q["query"], q["params"])
        results.extend(cursor.fetchall())
    return results

def read_and_search_offenders(filename, conn, start_date=None, end_date=None):
    """Read the file, search each item in the database within the date range, and return results."""
    with open(filename, 'r') as file:
        items = file.read().splitlines()

    results = []
    for item in items:
        item_results = query_database_for_offenders(conn, item, start_date, end_date)
        results.extend(item_results)

    return results

def process_known_offenders(db_path, ips_file, start_date, end_date):
    """Process known offenders from the provided file and query the database."""
    conn = create_connection(db_path)
    if conn:
        results = read_and_search_offenders(ips_file, conn, start_date, end_date)
        conn.close()
        return results
    else:
        print("Failed to create database connection.")
        return []