import pandas as pd
import glob
import datetime
import matplotlib.pyplot as plt
import numpy as np 
from scipy.stats import entropy

def is_file_in_date_range(filename, start_date, end_date):
    """Check if the file's date falls within the specified date range."""
    file_date_str = filename.split('/')[-1].split('VPNAuthentications.csv')[0].split('-')[1]
    file_date = datetime.datetime.strptime(file_date_str, '%Y%m%d').date()
    return start_date <= file_date <= end_date

failed_attempts_by_ip_portal = {}
success_at_gateway_after_failure = {}

def get_user_date(prompt):
    while True:
        date_input = input(prompt)
        try:
            return datetime.datetime.strptime(date_input, '%Y-%m-%d').date()
        except ValueError:
            print("The date format should be YYYY-MM-DD. Please try again.")

start_date = get_user_date("Enter the start date (YYYY-MM-DD): ")
end_date = get_user_date("Enter the end date (YYYY-MM-DD): ")

all_files = glob.glob('VPNlogs/*.csv')
filtered_files = [file for file in all_files if is_file_in_date_range(file, start_date, end_date)]

df = pd.concat((pd.read_csv(f) for f in filtered_files), ignore_index=True)
df.rename(columns={'public_ip': 'IP Address', 'Source User': 'Username'}, inplace=True)

df['Generate Time'] = pd.to_datetime(df['Generate Time'])
df.sort_values(by='Generate Time', inplace=True)

df['srcregion'] = df.groupby('IP Address')['srcregion'].ffill()
df['srcregion'].fillna('Unknown', inplace=True)

date_range_label = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"

for index, row in df.iterrows():
    ip = row['IP Address']
    eventid = row['eventid']
    status = row['status'] 
    
    if eventid == 'portal-auth' and status == 'failure':
        if ip not in failed_attempts_by_ip_portal:
            failed_attempts_by_ip_portal[ip] = 0
        failed_attempts_by_ip_portal[ip] += 1
    
    elif eventid == 'gateway-auth' and status == 'success':
        if ip in failed_attempts_by_ip_portal:
            failed_attempts = failed_attempts_by_ip_portal[ip]
            if failed_attempts >= 1:  # Threshold
                success_at_gateway_after_failure[ip] = failed_attempts
                print(f"ALERT: IP {ip} had {failed_attempts} failed portal-auth attempts before a successful gateway-auth.")
            del failed_attempts_by_ip_portal[ip]

login_attempts_by_country = df.groupby('srcregion').size().sort_values(ascending=False).head(10)
login_attempts_by_country.plot(kind='bar', figsize=(10, 6), title=f'Top 10 Login Attempts by Country ({date_range_label})')
plt.xlabel('Country')
plt.ylabel('Number of Login Attempts')
plt.tight_layout()
plt.savefig('top_10_login_attempts_by_country.png')

failed_logins_df = df[df['status'] == 'failure'].copy()

failed_login_counts = failed_logins_df.groupby('IP Address').size()
mean_attempts = failed_login_counts.mean()
std_attempts = failed_login_counts.std()

z_scores = (failed_login_counts - mean_attempts) / std_attempts
failed_logins_df['z_score'] = failed_logins_df['IP Address'].map(z_scores)

outliers = failed_logins_df[failed_logins_df['z_score'] > 3]

max_z_scores = outliers.groupby(['IP Address', 'srcregion'])['z_score'].max().reset_index()

outlier_summary = max_z_scores.merge(
    outliers.groupby(['IP Address', 'srcregion']).size().reset_index(name='Total Attempts'),
    on=['IP Address', 'srcregion'],
    how='left'
).sort_values(by='Total Attempts', ascending=False)

print("\nIPs with unusual number of login attempts (Outliers), their country codes, and Z-scores:")
for index, row in outlier_summary.iterrows():
    print(f"{row['IP Address']} ({row['srcregion']}): {row['Total Attempts']} attempts (Z-score: {row['z_score']:.2f})")

df['date'] = df['Generate Time'].dt.date

daily_login_attempts = df.groupby(['date', 'IP Address']).size().unstack(fill_value=0)

daily_entropy = daily_login_attempts.apply(entropy, axis=1)

mean_entropy = daily_entropy.mean()
std_entropy = daily_entropy.std()
anomaly_threshold = mean_entropy + 2 * std_entropy  # Entropy threshold
anomaly_days = daily_entropy[daily_entropy > anomaly_threshold]

print("\nDays with unusually high login randomness (potential anomalies):")
if not anomaly_days.empty:
    for date, entropy_value in anomaly_days.iteritems():
        print(f"{date}: {entropy_value}")
else:
    print("No days with unusually high login randomness were detected.")

plt.figure(figsize=(10, 6))
daily_entropy.plot(title=f'Daily Login Attempt Entropy ({date_range_label})')
plt.axhline(y=anomaly_threshold, color='r', linestyle='--', label='Anomaly Threshold')
plt.xlabel('Date')
plt.ylabel('Entropy')
plt.legend()
plt.tight_layout()
plt.savefig('daily_login_entropy.png')

plt.figure(figsize=(10, 6))
df['hour'] = df['Generate Time'].dt.hour
login_attempts_by_hour = df.groupby('hour').size()
login_attempts_by_hour.plot(kind='bar', figsize=(10, 6), title=f'Login Attempts by Hour ({date_range_label})')
plt.xlabel('Hour of the Day')
plt.ylabel('Number of Attempts')
plt.tight_layout()
plt.savefig('login_attempts_by_hour.png')

ip_to_region = failed_logins_df[['IP Address', 'srcregion']].drop_duplicates()

unique_usernames_per_ip = failed_logins_df.groupby('IP Address')['Username'].nunique().reset_index(name='Unique Usernames').sort_values(by='Unique Usernames', ascending=False)

unique_usernames_per_ip_with_region = unique_usernames_per_ip.merge(ip_to_region, on='IP Address', how='left')

unique_usernames_per_ip_with_region['IP Address'] = unique_usernames_per_ip_with_region['IP Address'] + " (" + unique_usernames_per_ip_with_region['srcregion'] + ")"

print(f"\nTop 10 IPs by Unique Username Attempts with Source Region:\n")
print(unique_usernames_per_ip_with_region[['IP Address', 'Unique Usernames']].head(10).to_string(index=False))

total_attempts_per_ip = failed_logins_df.groupby(['IP Address', 'srcregion']).size().reset_index(name='Total Attempts').sort_values(by='Total Attempts', ascending=False)
total_attempts_per_ip['IP Address'] = total_attempts_per_ip.apply(lambda x: f"{x['IP Address']} ({x['srcregion']})", axis=1)

plt.figure(figsize=(10, 6))
plt.barh(total_attempts_per_ip['IP Address'].head(10), total_attempts_per_ip['Total Attempts'].head(10))
plt.xlabel('Number of Failed Login Attempts')
plt.ylabel('IP Address')
plt.title(f'Top 10 IP Addresses by Failed Login Attempts ({date_range_label})')
plt.tight_layout()
plt.savefig('total_attempts_per_ip_with_country.png')

print("\nTop 10 IPs by Total Number of Attempts:\n")
print(total_attempts_per_ip[['IP Address', 'Total Attempts']].head(10).to_string(index=False))

df['Generate Time'] = pd.to_datetime(df['Generate Time'])

df['date'] = df['Generate Time'].dt.date

df['status'] = df['status'].str.capitalize() 

daily_counts = df.groupby(['date', 'status']).size().unstack(fill_value=0)

print("\nDaily Counts of Successes and Failures:")
for date, row in daily_counts.iterrows():
    print(f"{date}: Successes = {row.get('Success', 0)}, Failures = {row.get('Failure', 0)}")

total_successes = daily_counts['Success'].sum()
total_failures = daily_counts['Failure'].sum()
print(f"\nTotal Successes: {total_successes}, Total Failures: {total_failures}")