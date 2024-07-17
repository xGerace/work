import sqlite3
import logging
from typing import Optional, List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_connection(db_file: str = "panorama_logs.db") -> Optional[sqlite3.Connection]:
    try:
        conn = sqlite3.connect(db_file)
        logger.info(f"Database connection established to {db_file}")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error creating connection: {e}")
        return None

def execute_query(conn: sqlite3.Connection, query: str, params: Tuple = ()) -> List[Tuple]:
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        logger.info(f"Executed query: {query} with params: {params}")
        return rows
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e}")
        return []