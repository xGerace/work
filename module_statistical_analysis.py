import pandas as pd
from module_database import execute_query
from module_utility import build_conditions
import logging
import sqlite3
from datetime import datetime
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fetch_failed_logins(conn: sqlite3.Connection, start_datetime: datetime, end_datetime: datetime) -> List[Tuple]:
    conditions, params = build_conditions(start_datetime, end_datetime)
    query = f"""
    SELECT IP_Address, Source_Region, Status
    FROM GlobalProtectLogs
    WHERE {conditions} AND Status = 'failure';
    """
    return execute_query(conn, query, params)

def perform_statistical_analysis(data: List[Tuple]) -> pd.DataFrame:
    df = pd.DataFrame(data, columns=['IP_Address', 'Source_Region', 'Status'])
    failed_logins_df = df[df['Status'] == 'failure'].copy()

    failed_login_counts = failed_logins_df.groupby('IP_Address').size()
    mean_attempts = failed_login_counts.mean()
    std_attempts = failed_login_counts.std()

    z_scores = (failed_login_counts - mean_attempts) / std_attempts
    failed_logins_df['z_score'] = failed_logins_df['IP_Address'].map(z_scores)

    outliers = failed_logins_df[failed_logins_df['z_score'] > 3]

    max_z_scores = outliers.groupby(['IP_Address', 'Source_Region'])['z_score'].max().reset_index()

    outlier_summary = max_z_scores.merge(
        outliers.groupby(['IP_Address', 'Source_Region']).size().reset_index(name='Total Attempts'),
        on=['IP_Address', 'Source_Region'],
        how='left'
    ).sort_values(by='Total Attempts', ascending=False)

    logger.info(f"Identified {len(outlier_summary)} outliers in failed login attempts.")
    return outlier_summary