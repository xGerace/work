import sqlite3
from sqlite3 import Error

def create_connection(db_file):
    """Create a database connection to the specified SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print("SQLite version:", sqlite3.version)
        return conn
    except Error as e:
        print(e)
    return conn

def create_table(conn, create_table_sql):
    """Create a table from the create_table_sql statement."""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

def main():
    database = "./panorama_logs.db"

    # SQL table creation statements for each log type
    sql_create_traffic_table = """CREATE TABLE IF NOT EXISTS TrafficLogs (
                                    id INTEGER PRIMARY KEY,
                                    Time_Generated DATETIME NOT NULL,
                                    IP_Address TEXT,
                                    Destination_IP TEXT,
                                    Source_Region TEXT,
                                    Destination_Region TEXT,
                                    Application TEXT,
                                    Action TEXT,
                                    Proto TEXT,
                                    Bytes INTEGER,
                                    Packets INTEGER,
                                    Session_End_Reason TEXT,
                                    Rule TEXT,
                                    Suspicion_Level INTEGER CHECK (Suspicion_Level BETWEEN 1 AND 10),
                                    Additional_Data TEXT,
                                    UNIQUE(Time_Generated, IP_Address, Destination_IP)
                                );"""


    sql_create_threat_table = """CREATE TABLE IF NOT EXISTS ThreatLogs (
                                   id INTEGER PRIMARY KEY,
                                   Time_Generated DATETIME NOT NULL,
                                   IP_Address TEXT,
                                   Destination_IP TEXT,
                                   Source_Region TEXT,
                                   Destination_Region TEXT,
                                   Application TEXT,
                                   Action TEXT,
                                   Threat_ID TEXT,
                                   Threat_Name TEXT,
                                   Severity TEXT,
                                   Category TEXT,
                                   Suspicion_Level INTEGER CHECK (suspicion_level BETWEEN 1 AND 10),
                                   Additional_Data TEXT,
                                   UNIQUE(Time_Generated, IP_Address, Threat_ID)
                                 );"""

    sql_create_globalprotect_table = """CREATE TABLE IF NOT EXISTS GlobalProtectLogs (
                                        id INTEGER PRIMARY KEY,
                                        Time_Generated DATETIME NOT NULL,
                                        IP_Address TEXT,
                                        Source_Region TEXT,
                                        Source_User TEXT,
                                        Portal TEXT,
                                        Event_ID TEXT,
                                        Status TEXT,
                                        Suspicion_Level INTEGER CHECK (suspicion_level BETWEEN 1 AND 10),
                                        Additional_Data TEXT,
                                        UNIQUE(Time_Generated, IP_Address, Event_ID)
                                        );"""

    # Create a database connection
    conn = create_connection(database)

    # Create tables
    if conn is not None:
        create_table(conn, sql_create_traffic_table)
        create_table(conn, sql_create_threat_table)
        create_table(conn, sql_create_globalprotect_table)
        print("Tables created successfully.")
        conn.close()
    else:
        print("Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()
