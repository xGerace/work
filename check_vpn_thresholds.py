import csv
import glob

# Define the thresholds
IP_THRESHOLD = 50  # Threshold for IP checks
USER_IP_THRESHOLD = 15  # Threshold for user+IP checks

def find_csv_filenames(path_to_dir, suffix=".csv"):
    filenames = glob.glob(path_to_dir + "/*" + suffix)
    return [filename for filename in filenames if "VPNAuthentications" in filename]

def analyze_csv(filename):
    ip_country_mapping = {}  # Store the most recent non-empty country code seen for an IP
    ip_details = {}  # Store counts and country codes for IPs
    user_ip_counts = {}  # Count occurrences by user and IP

    with open(filename, mode='r', encoding='utf-8-sig') as file:  # Note the encoding change here
        reader = csv.DictReader(file)
        # Dynamically remove BOM or other unexpected leading characters from column names
        reader.fieldnames = [name.encode('utf-8').decode('utf-8-sig').strip() for name in reader.fieldnames]

        for row in reader:
            ip = row['public_ip'].replace('\n', '').replace('\r', '')
            user = row['Source User'].strip().replace('\n', '').replace('\r', '')
            # Remove domain prefix if present and convert to lowercase
            user = user.split('\\')[-1].lower()
            country = row['srcregion'].strip().replace('\n', '').replace('\r', '')

            # If a country code is available, update the mapping for the IP
            if country:
                ip_country_mapping[ip] = country
            # If the country is not set yet for this IP, default to "Unknown"
            elif ip not in ip_country_mapping:
                ip_country_mapping[ip] = "Unknown"

            # Use the known or default country code for the IP
            country_code = ip_country_mapping[ip]

            # Skip entries with blank usernames
            if not user:
                continue

            # Key for tracking user-IP combinations
            user_ip_key = f"{user}||{ip}"

            # Update IP details with counts and country codes
            if ip in ip_details:
                ip_details[ip]['count'] += 1
                # Ensure the country code is updated if it's not "Unknown"
                if country_code != "Unknown":
                    ip_details[ip]['country'] = country_code
            else:
                ip_details[ip] = {'count': 1, 'country': country_code}

            # Count user-IP combinations
            user_ip_counts[user_ip_key] = user_ip_counts.get(user_ip_key, 0) + 1

    return ip_details, user_ip_counts, ip_country_mapping

def print_exceeds_threshold_ip(ip_details):
    sorted_ips = sorted(ip_details.items(), key=lambda item: item[1]['count'], reverse=True)
    for ip, details in sorted_ips:
        if details['count'] > IP_THRESHOLD:
            country = details['country'] if details['country'] else "Unknown"
            print(f"IP Address '{ip}' - country '{country}' - {details['count']} attempts.")

def print_exceeds_threshold_user_ip(user_ip_counts, ip_country_mapping):
    sorted_user_ips = sorted(user_ip_counts.items(), key=lambda item: item[1], reverse=True)
    for user_ip, count in sorted_user_ips:
        if count > USER_IP_THRESHOLD:
            user, ip = user_ip.split("||")
            country = ip_country_mapping.get(ip, "Unknown")  # Get the country for the IP
            # Skip printing for blank usernames
            if user == "":
                continue
            print(f"Username '{user}' - IP '{ip}' - country '{country}' - {count} attempts.")

def main():
    csv_filenames = find_csv_filenames(".")
    for filename in csv_filenames:
        print(f"\nAnalyzing {filename}...\n")
        ip_details, user_ip_counts, ip_country_mapping = analyze_csv(filename)

        # Check for IPs exceeding threshold including country code, sorted by count
        print_exceeds_threshold_ip(ip_details)

        # For user-IP combinations, print the details, sorted by count, including country
        print_exceeds_threshold_user_ip(user_ip_counts, ip_country_mapping)

if __name__ == "__main__":
    main()