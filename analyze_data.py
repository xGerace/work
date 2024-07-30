import requests
import sqlite3
from urllib.parse import quote
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
import os
import time
import re

load_dotenv()

def create_connection(db_file):
    """Create a database connection to a SQLite database specified by db_file"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(e)
    return conn

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

def validate_log_type(log_type):
    """Validate the log type input"""
    valid_log_types = ['traffic', 'threat', 'globalprotect']
    if log_type not in valid_log_types:
        raise ValueError(f"Invalid log type. Expected one of {valid_log_types}, but got '{log_type}'")

def validate_date(input_date):
    """Validate date format YYYY-MM-DD"""
    if input_date and not re.match(r'\d{4}-\d{2}-\d{2}', input_date):
        raise ValueError(f"Invalid date format. Expected 'YYYY-MM-DD', but got '{input_date}'")

def validate_time(input_time):
    """Validate time format HH:MM"""
    if input_time and not re.match(r'\d{2}:\d{2}', input_time):
        raise ValueError(f"Invalid time format. Expected 'HH:MM', but got '{input_time}'")

def get_valid_input(prompt, validation_function, error_message):
    while True:
        user_input = input(prompt).strip()
        try:
            validation_function(user_input)
            break  # Exit the loop if validation passes
        except ValueError:
            print(f"Invalid input. {error_message}")
    return user_input

if __name__ == '__main__':
    conn = create_connection("panorama_logs.db")

    log_type = get_valid_input(
        "Enter the log type (e.g., 'traffic', 'threat', 'globalprotect'): ",
        validate_log_type,
        "Expected one of 'traffic', 'threat', 'globalprotect'. Please try again."
    )

    specified_start_date = get_valid_input(
        "Enter the start date you want to fetch logs for (YYYY-MM-DD) or press Enter for today's date: ",
        lambda x: validate_date(x or datetime.now().strftime('%Y-%m-%d')),
        "Date should be in YYYY-MM-DD format or press Enter for today's date."
    )
    specified_start_date = specified_start_date or datetime.now().strftime('%Y-%m-%d')

    start_time_input = get_valid_input(
        "Enter the start time (HH:MM) or press Enter for one hour before now: ",
        lambda x: validate_time(x or (datetime.now() - timedelta(hours=1)).strftime('%H:%M')),
        "Time should be in HH:MM format or press Enter for one hour before now."
    )
    start_time_input = start_time_input or (datetime.now() - timedelta(hours=1)).strftime('%H:%M')

    specified_end_date = get_valid_input(
        f"Enter the end date you want to fetch logs for (YYYY-MM-DD) or press Enter to use the start date {specified_start_date}: ",
        lambda x: validate_date(x or specified_start_date),
        "Date should be in YYYY-MM-DD format or press Enter to use the start date."
    )
    specified_end_date = specified_end_date or specified_start_date

    end_time_input = get_valid_input(
        "Enter the end time (HH:MM) or press Enter for one hour after the start time: ",
        lambda x: validate_time(x or (datetime.strptime(f"{specified_start_date} {start_time_input}", '%Y-%m-%d %H:%M') + timedelta(hours=1)).strftime('%H:%M')),
        "Time should be in HH:MM format or press Enter for one hour after the start time."
    )
    if not end_time_input:
        start_time = datetime.strptime(f"{specified_start_date} {start_time_input}", '%Y-%m-%d %H:%M')
        end_time_input = (start_time + timedelta(hours=1)).strftime('%H:%M')

    start_datetime = datetime.strptime(f"{specified_start_date} {start_time_input}", '%Y-%m-%d %H:%M')
    end_datetime = datetime.strptime(f"{specified_end_date} {end_time_input}", '%Y-%m-%d %H:%M')

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

        start_datetime = next_hour

    print("Completed fetching and processing logs.")
