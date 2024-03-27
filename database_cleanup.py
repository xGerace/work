import sqlite3
from sqlite3 import Error

def create_connection(db_file):
    """Create a database connection to the SQLite database specified by db_file."""
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return None

def delete_old_records(conn, days_old):
    """Delete records older than a specified number of days from all tables."""
    retention_period = f"-{days_old} day"  # Define retention period
    delete_queries = [
        f"DELETE FROM GlobalProtectLogs WHERE Time_Generated < DATE('now', '{retention_period}')",
        f"DELETE FROM ThreatLogs WHERE Time_Generated < DATE('now', '{retention_period}')",
        f"DELETE FROM TrafficLogs WHERE Time_Generated < DATE('now', '{retention_period}')"
    ]
    try:
        cur = conn.cursor()
        for query in delete_queries:
            cur.execute(query)
            print(f"Deleted old records from table: {query.split(' ')[2]}")
        conn.commit()
    except Error as e:
        print("Error deleting old records:", e)

def main():
    database_path = "./panorama_logs.db"  # Update this path to your database file
    conn = create_connection(database_path)
    if conn:
        delete_old_records(conn, 60)  # Specify the number of days for data retention
        conn.close()
        print("Data retention policy enforcement complete.")
    else:
        print("Error! Cannot create the database connection.")

if __name__ == "__main__":
    main()