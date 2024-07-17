from datetime import datetime, timedelta
import os
import pandas as pd
from dotenv import load_dotenv
from module_database import execute_query
from module_utility import print_query_results
import sqlite3
import logging
from typing import List, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

def get_date_input(prompt: str) -> Tuple[Optional[datetime], Optional[datetime]]:
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
    logger.warning("Invalid date format entered. Please use formats like YYYY, YYYY/MM, YYYY/MM/DD HH:MM, etc.")
    return None, None

def get_user_confirmation(prompt: str) -> bool:
    user_input = input(prompt).lower()
    return user_input in ['yes', 'y']

def threat_analysis(conn: sqlite3.Connection, start_datetime: datetime, end_datetime: datetime, exclude_own_ips: bool) -> str:
    ip_exclusion_condition = "AND IP_Address NOT LIKE '" + os.getenv('ORG_IP_PREFIX') + ".%' " if exclude_own_ips else ""

    params = [start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")]

    summary = ""

    query_threat_ids = f"""
    SELECT Threat_ID, Severity, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY Threat_ID, Severity
    ORDER BY Count DESC
    LIMIT 10;
    """
    summary += "\nTop 10 Threat IDs by count with severity:\n"
    results = execute_query(conn, query_threat_ids, params)
    summary += print_query_results(results, ["Threat ID", "Severity", "Count"])

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
    summary += "\nThreat count by country:\n"
    results = execute_query(conn, query_country, params)
    summary += print_query_results(results, ["Country", "Threats"])

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
    summary += "\nTop 10 IP addresses by threat count:\n"
    results = execute_query(conn, query_top_ips, params)
    summary += print_query_results(results, ["IP Address", "Source Region", "Threat Count"])

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
    summary += "\nBreakdown of threats by severity:\n"
    results = execute_query(conn, query_severity, params)
    summary += print_query_results(results, ["Severity", "Count"])

    query_actions = f"""
    SELECT Action, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY Action
    ORDER BY Count DESC;
    """
    summary += "\nCount of each type of Action:\n"
    results = execute_query(conn, query_actions, params)
    summary += print_query_results(results, ["Action", "Count"])

    query_daily = f"""
    SELECT strftime('%Y-%m-%d', replace(Time_Generated, '/', '-')) AS Date, COUNT(*) AS Daily_Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ? {ip_exclusion_condition}
    GROUP BY strftime('%Y-%m-%d', replace(Time_Generated, '/', '-'))
    ORDER BY Date DESC;
    """
    summary += "\nDaily count of threats:\n"
    results = execute_query(conn, query_daily, params)
    summary += print_query_results(results, ["Date", "Daily Count"])

    return summary

def fetch_threat_counts_by_day(conn: sqlite3.Connection, start_datetime: datetime, end_datetime: datetime) -> pd.DataFrame:
    query = """
    SELECT strftime('%Y-%m-%d', replace(Time_Generated, '/', '-')) AS Date, COUNT(*) AS Count
    FROM ThreatLogs
    WHERE Time_Generated >= ? AND Time_Generated <= ?
    GROUP BY Date
    ORDER BY Date;
    """
    params = [start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")]
    results = execute_query(conn, query, params)
    return pd.DataFrame(results, columns=["Date", "Count"]).set_index("Date")