#!/usr/bin/env python3
import json
import re
from datetime import datetime, timedelta

def count_threats(file_path):
    threat_type_count = {}
    threat_status_count = {}
    total_threat_count = 0
    clicks_blocked_count = 0
    clicks_permitted_count = 0
    messages_blocked_count = 0
    messages_delivered_count = 0
    seven_days_ago = datetime.now() - timedelta(days=7)

    with open(file_path, 'r') as file:
        file_content = file.read()

    # Splitting the file content into individual JSON objects
    json_objects = re.split(r'}\s*{', file_content)

    for json_obj_str in json_objects:
        try:
            # Ensuring each segment is a valid JSON object
            if not json_obj_str.startswith('{'):
                json_obj_str = '{' + json_obj_str
            if not json_obj_str.endswith('}'):
                json_obj_str += '}'

            data = json.loads(json_obj_str)

            clicks_blocked_count += len(data.get("clicksBlocked", []))
            clicks_permitted_count += len(data.get("clicksPermitted", []))
            messages_blocked_count += len(data.get("messagesBlocked", []))
            messages_delivered_count += len(data.get("messagesDelivered", []))

            for message_type in ["messagesDelivered", "messagesBlocked"]:
                for message in data.get(message_type, []):
                    for threat in message.get("threatsInfoMap", []):
                        threat_time_str = threat.get("threatTime")
                        if threat_time_str:
                            threat_time = datetime.fromisoformat(threat_time_str.rstrip("Z"))
                            if threat_time >= seven_days_ago:
                                total_threat_count += 1
                                threat_type = threat.get("threatType", "unknown")
                                threat_status = threat.get("threatStatus", "unknown")

                                threat_type_count[threat_type] = threat_type_count.get(threat_type, 0) + 1
                                threat_status_count[threat_status] = threat_status_count.get(threat_status, 0) + 1
        except json.JSONDecodeError:
            continue  # Skip over any non-JSON text or partial JSON objects

    return total_threat_count, threat_type_count, threat_status_count, clicks_blocked_count, clicks_permitted_count, messages_blocked_count, messages_delivered_count

file_path = 'combined-tap-siem.log'
total_threat_count, threat_type_count, threat_status_count, clicks_blocked_count, clicks_permitted_count, messages_blocked_count, messages_delivered_count = count_threats(file_path)

print(f"\nThreat Type Counts:", threat_type_count)
print("Threat Status Counts:", threat_status_count)
print("Total Threat Count:", total_threat_count)
print("Clicks Blocked Count:", clicks_blocked_count)
print("Clicks Permitted Count:", clicks_permitted_count)
print("Messages Blocked Count:", messages_blocked_count)
print("Messages Delivered Count:", messages_delivered_count)
