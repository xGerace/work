import sqlite3
import logging
from typing import List, Tuple, Optional
from module_database import create_connection

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def query_database_for_offenders(conn: sqlite3.Connection, item: str, start_date: str, end_date: str) -> List[Tuple]:
    queries = [
        {
            "query": """
            SELECT 'ThreatLogs', MIN(Time_Generated), MAX(Time_Generated), COUNT(*), GROUP_CONCAT(DISTINCT IP_Address), GROUP_CONCAT(DISTINCT Destination_IP), GROUP_CONCAT(DISTINCT Source_Region)
            FROM ThreatLogs WHERE (IP_Address = ? OR Destination_IP = ?)
            AND Time_Generated BETWEEN ? AND ?
            """,
            "params": (item, item, start_date + " 00:00:00", end_date + " 23:59:59")
        },
        {
            "query": """
            SELECT 'GlobalProtectLogs', MIN(Time_Generated), MAX(Time_Generated), COUNT(*), GROUP_CONCAT(DISTINCT IP_Address), GROUP_CONCAT(DISTINCT Source_User), GROUP_CONCAT(DISTINCT Source_Region)
            FROM GlobalProtectLogs WHERE (IP_Address = ? OR Source_User = ?)
            AND Time_Generated BETWEEN ? AND ?
            """,
            "params": (item, item, start_date + " 00:00:00", end_date + " 23:59:59")
        }
    ]

    results = []
    cursor = conn.cursor()
    for q in queries:
        cursor.execute(q["query"], q["params"])
        results.extend(cursor.fetchall())
    return results

def read_and_search_offenders(filename: str, conn: sqlite3.Connection, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Tuple]:
    with open(filename, 'r') as file:
        items = file.read().splitlines()

    results = []
    for item in items:
        item_results = query_database_for_offenders(conn, item, start_date, end_date)
        results.extend(item_results)

    return results

def process_known_offenders(db_path: str, ips_file: str, start_date: str, end_date: str) -> List[Tuple]:
    conn = create_connection(db_path)
    if conn:
        results = read_and_search_offenders(ips_file, conn, start_date, end_date)
        conn.close()
        logger.info("Processed known offenders from database.")
        return results
    else:
        logger.error("Failed to create database connection.")
        return []