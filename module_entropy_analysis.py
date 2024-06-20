import pandas as pd
import numpy as np
from scipy.stats import entropy
from module_database import execute_query
from module_utility import build_conditions

def fetch_login_data(conn, start_datetime, end_datetime):
    conditions, params = build_conditions(start_datetime, end_datetime)
    query = f"""
    SELECT substr(Time_Generated, 1, 10) as date, IP_Address
    FROM GlobalProtectLogs
    WHERE {conditions};
    """
    return execute_query(conn, query, params)

def calculate_entropy(df):
    daily_login_attempts = df.groupby(['date', 'IP_Address']).size().unstack(fill_value=0)
    daily_entropy = daily_login_attempts.apply(lambda x: entropy(x, base=2), axis=1)
    return daily_entropy

def identify_anomalies(daily_entropy):
    mean_entropy = daily_entropy.mean()
    std_entropy = daily_entropy.std()
    anomaly_threshold = mean_entropy + 2 * std_entropy
    anomaly_days = daily_entropy[daily_entropy > anomaly_threshold]
    return anomaly_days, anomaly_threshold