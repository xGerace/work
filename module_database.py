import sqlite3

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