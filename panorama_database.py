import requests
import sqlite3
from urllib.parse import quote
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
import os
import time

load_dotenv()

# Database interaction functions
def create_connection(db_file):
    """Create a database connection to a SQLite database specified by db_file"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(e)
    return conn

def get_latest_log_time(conn, log_type):
    cur = conn.cursor()
    table_name = f"{log_type.capitalize()}Logs" 
    cur.execute(f"SELECT MAX(Time_Generated) FROM {table_name}")
    last_time = cur.fetchone()[0]
    if last_time is not None:
        # If there is a latest time in the database, return it as a datetime object
        return datetime.strptime(last_time, '%Y/%m/%d %H:%M:%S')
    else:
        # If there are no entries, default to a time far in the past to start fetching from the earliest possible logs
        return datetime.strptime('2024/01/01 00:00:00', '%Y/%m/%d %H:%M:%S')

def insert_traffic_log(conn, log_entry):
    sql = '''INSERT INTO TrafficLogs(Time_Generated, IP_Address, Destination_IP, Source_Region, Destination_Region,
                                     Application, Action, Proto, Bytes, Packets, Session_End_Reason, Rule,
                                     Suspicion_Level, Additional_Data)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(Time_Generated, IP_Address, Destination_IP) DO UPDATE SET
             Source_Region=excluded.Source_Region, Destination_Region=excluded.Destination_Region, Application=excluded.Application, 
             Action=excluded.Action, Proto=excluded.Proto, Bytes=excluded.Bytes, 
             Packets=excluded.Packets, Session_End_Reason=excluded.Session_End_Reason, 
             Rule=excluded.Rule, Suspicion_Level=excluded.Suspicion_Level, 
             Additional_Data=excluded.Additional_Data'''
    cur = conn.cursor()
    cur.execute(sql, log_entry)
    conn.commit()

def insert_threat_log(conn, log_entry):
    sql = '''INSERT INTO ThreatLogs(Time_Generated, IP_Address, Destination_IP, Source_Region, Destination_Region,
                                    Application, Action, Threat_ID, Threat_Name, Severity, Category,
                                    Suspicion_Level, Additional_Data)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(Time_Generated, IP_Address, Threat_ID) DO UPDATE SET
             Destination_IP=excluded.Destination_IP, Source_Region=excluded.Source_Region, 
             Destination_Region=excluded.Destination_Region, Application=excluded.Application, 
             Action=excluded.Action, Threat_ID=excluded.Threat_ID, Threat_Name=excluded.Threat_Name,
             Severity=excluded.Severity, Category=excluded.Category, Suspicion_Level=excluded.Suspicion_Level, 
             Additional_Data=excluded.Additional_Data'''
    cur = conn.cursor()
    cur.execute(sql, log_entry)
    conn.commit()

def insert_globalprotect_log(conn, log_entry):
    sql = '''INSERT INTO GlobalProtectLogs(Time_Generated, IP_Address, Source_Region, Source_User, Portal,
                                           Event_ID, Status, Suspicion_Level, Additional_Data)
             VALUES(?,?,?,?,?,?,?,?,?)
             ON CONFLICT(Time_Generated, IP_Address, Event_ID) DO UPDATE SET
             Source_Region=excluded.Source_Region, Source_User=excluded.Source_User, 
             Portal=excluded.Portal, Status=excluded.Status, Suspicion_Level=excluded.Suspicion_Level, 
             Additional_Data=excluded.Additional_Data'''
    cur = conn.cursor()
    cur.execute(sql, log_entry)
    conn.commit()

# Panorama API interaction functions
def initiate_log_query(conn, log_type, start_time, end_time):
    PANORAMA_HOST = os.getenv('PANORAMA_ENDPOINT')
    API_KEY = os.getenv('PANORAMA_API_KEY')
    query_url = f"https://{PANORAMA_HOST}/api/?type=log&log-type={log_type}&key={quote(API_KEY)}&query=(time_generated geq '{start_time}') and (time_generated leq '{end_time}')&nlogs=5000"
    response = requests.get(query_url, verify=True)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        job_id = root.find('.//job').text
        return job_id
    else:
        print(f"Failed to initiate log query: {response.status_code}, Response: {response.text}")
        return None

def check_job_status(conn, job_id):
    PANORAMA_HOST = os.getenv('PANORAMA_ENDPOINT')
    API_KEY = os.getenv('PANORAMA_API_KEY')
    status_url = f"https://{PANORAMA_HOST}/api/?type=log&action=get&job-id={job_id}&key={quote(API_KEY)}"
    while True:
        response = requests.get(status_url, verify=True)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            job_status = root.find('.//status').text
            if job_status == 'FIN': 
                return True
            else:
                time.sleep(10) 
        else:
            print("Failed to check job status:", response.text)
            return False

def fetch_and_process_logs(conn, log_type, job_id):
    logs_url = f"https://{os.getenv('PANORAMA_ENDPOINT')}/api/?type=log&action=get&job-id={job_id}&key={quote(os.getenv('PANORAMA_API_KEY'))}"
    response = requests.get(logs_url, verify=True)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        entries = root.findall('.//entry')
        for entry in entries:
            if log_type == "traffic":
                log_entry = prepare_traffic_log_entry(entry)
                insert_traffic_log(conn, log_entry)
            elif log_type == "threat":
                log_entry = prepare_threat_log_entry(entry)
                insert_threat_log(conn, log_entry)
            elif log_type == "globalprotect":
                log_entry = prepare_globalprotect_log_entry(entry)
                insert_globalprotect_log(conn, log_entry)

def prepare_traffic_log_entry(entry):
    return (
        entry.find('time_generated').text if entry.find('time_generated') is not None else "N/A",
        entry.find('src').text if entry.find('src') is not None else "N/A",
        entry.find('dst').text if entry.find('dst') is not None else "N/A",
        entry.find('srcloc').text if entry.find('srcloc') is not None else "N/A",
        entry.find('dstloc').text if entry.find('dstloc') is not None else "N/A",
        entry.find('app').text if entry.find('app') is not None else "N/A",
        entry.find('action').text if entry.find('action') is not None else "N/A",
        entry.find('proto').text if entry.find('proto') is not None else "N/A",
        int(entry.find('bytes').text) if entry.find('bytes') is not None else 0,
        int(entry.find('packets').text) if entry.find('packets') is not None else 0,
        entry.find('session_end_reason').text if entry.find('session_end_reason') is not None else "N/A",
        entry.find('rule').text if entry.find('rule') is not None else "N/A",
        1,  # Default Suspicion Level of 1
        ""  # Start with empty Additional_Data 
    )

def prepare_threat_log_entry(entry):
    return (
        entry.find('time_generated').text if entry.find('time_generated') is not None else "N/A",
        entry.find('src').text if entry.find('src') is not None else "N/A",
        entry.find('dst').text if entry.find('dst') is not None else "N/A",
        entry.find('srcloc').text if entry.find('srcloc') is not None else "N/A",
        entry.find('dstloc').text if entry.find('dstloc') is not None else "N/A",
        entry.find('app').text if entry.find('app') is not None else "N/A",
        entry.find('action').text if entry.find('action') is not None else "N/A",
        entry.find('threatid').text if entry.find('threatid') is not None else "N/A",
        entry.find('threat_name').text if entry.find('threat_name') is not None else "N/A",
        entry.find('severity').text if entry.find('severity') is not None else "N/A",
        entry.find('category').text if entry.find('category') is not None else "N/A",
        1,  # Default Suspicion Level of 1
        ""  # Start with empty Additional_Data
    )

def prepare_globalprotect_log_entry(entry):
    return (
        entry.find('time_generated').text if entry.find('time_generated') is not None else "N/A",
        entry.find('public_ip').text if entry.find('public_ip') is not None else "N/A",
        entry.find('srcregion').text if entry.find('srcregion') is not None else "N/A",
        entry.find('srcuser').text if entry.find('srcuser') is not None else "N/A",
        entry.find('portal').text if entry.find('portal') is not None else "N/A",
        entry.find('eventid').text if entry.find('eventid') is not None else "N/A",
        entry.find('status').text if entry.find('status') is not None else "N/A",
        1,  # Default Suspicion Level of 1
        ""  # Start with empty Additional_Data
    )

if __name__ == '__main__':
    conn = create_connection("panorama_logs.db")

    # Define log types to be processed automatically
    log_types = ['globalprotect', 'threat']

    for log_type in log_types:
        print(f"\nProcessing {log_type.capitalize()} logs...")
        
        # Retrieve the most recent log time for the current log type
        last_log_time = get_latest_log_time(conn, log_type)
        print(f"Last log time for {log_type} logs: {last_log_time.strftime('%Y/%m/%d %H:%M:%S')}")

        # Set start time to the last log time or current time if there are no entries
        start_datetime = last_log_time
        end_datetime = datetime.now()  # Current time as the endpoint for fetching logs

        while start_datetime < end_datetime:
            next_hour = start_datetime + timedelta(hours=1)
            formatted_start_time = start_datetime.strftime('%Y/%m/%d %H:%M:%S')
            formatted_end_time = min(next_hour, end_datetime).strftime('%Y/%m/%d %H:%M:%S')

            print(f"Fetching logs from {formatted_start_time} to {formatted_end_time} for log type '{log_type}'...")
            job_id = initiate_log_query(conn, log_type, formatted_start_time, formatted_end_time)
            if job_id:
                if check_job_status(conn, job_id):
                    fetch_and_process_logs(conn, log_type, job_id)
                else:
                    print("Failed to complete job within the expected time.")
            else:
                print("Failed to initiate job for the current hour.")

            start_datetime = next_hour  # Move to the next hour

        print(f"Completed fetching and processing {log_type.capitalize()} logs.")

    print("All log types have been processed.")