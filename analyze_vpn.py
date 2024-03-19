import pandas as pd
import glob
import datetime
import matplotlib.pyplot as plt
import numpy as np 
from scipy.stats import entropy

def is_file_in_date_range(filename, start_date, end_date):
    """Check if the file's date falls within the specified date range."""
    file_date_str = filename.split('/')[-1].split('VPNAuthentications.csv')[0].split('-')[1]
    file_date = datetime.datetime.strptime(file_date_str, '%Y%m%d').date() - datetime.timedelta(days=1)
    return start_date <= file_date <= end_date

start_date_input = input("Enter the start date (YYYY-MM-DD): ")
end_date_input = input("Enter the end date (YYYY-MM-DD): ")

start_date = datetime.datetime.strptime(start_date_input, '%Y-%m-%d').date()
end_date = datetime.datetime.strptime(end_date_input, '%Y-%m-%d').date()

all_files = glob.glob('VPNlogs/*.csv')
filtered_files = [file for file in all_files if is_file_in_date_range(file, start_date, end_date)]

df = pd.concat((pd.read_csv(f) for f in filtered_files), ignore_index=True)
df.rename(columns={'public_ip': 'IP Address', 'Source User': 'Username'}, inplace=True)

df['Generate Time'] = pd.to_datetime(df['Generate Time'])
df.sort_values(by='Generate Time', inplace=True)

df['srcregion'] = df.groupby('IP Address')['srcregion'].ffill()
df['srcregion'].fillna('Unknown', inplace=True)

date_range_label = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"

login_attempts_by_country = df.groupby('srcregion').size().sort_values(ascending=False).head(10)
login_attempts_by_country.plot(kind='bar', figsize=(10, 6), title=f'Top 10 Login Attempts by Country ({date_range_label})')
plt.xlabel('Country')
plt.ylabel('Number of Login Attempts')
plt.title(f'Top 10 Login Attempts by Country ({date_range_label})')
plt.tight_layout()
plt.savefig('top_10_login_attempts_by_country.png')

failed_logins_df = df[df['status'] == 'failure'].copy()

# Statistical Analysis: Calculate Z-scores for anomaly detection
failed_login_counts = failed_logins_df.groupby('IP Address').size()
mean_attempts = failed_login_counts.mean()
std_attempts = failed_login_counts.std()
failed_logins_df['z_score'] = failed_logins_df['IP Address'].map(failed_login_counts.sub(mean_attempts).div(std_attempts))

# Identify outlier IPs based on Z-scores
outliers = failed_logins_df[failed_logins_df['z_score'] > 3]['IP Address'].unique()

# Aggregate information for outlier IPs
outlier_info = failed_logins_df[failed_logins_df['IP Address'].isin(outliers)]
outlier_summary = outlier_info.groupby(['IP Address', 'srcregion']).size().reset_index(name='Total Attempts')

# Sort the outlier summary by 'Total Attempts' in descending order
outlier_summary = outlier_summary.sort_values(by='Total Attempts', ascending=False)

print("\nIPs with unusual number of login attempts (Outliers) and their country codes:")
if not outlier_summary.empty:
    for index, row in outlier_summary.iterrows():
        print(f"{row['IP Address']} ({row['srcregion']}): {row['Total Attempts']} attempts")
else:
    print("No outlier IPs with unusually high login attempts were detected.")

# Add a 'date' column to df for daily analysis
df['date'] = df['Generate Time'].dt.date

# Calculate the daily number of login attempts per IP
daily_login_attempts = df.groupby(['date', 'IP Address']).size().unstack(fill_value=0)

# Calculate the entropy for each day
daily_entropy = daily_login_attempts.apply(entropy, axis=1)

# Identify days with significantly higher entropy than the mean, suggesting anomalies
mean_entropy = daily_entropy.mean()
std_entropy = daily_entropy.std()
anomaly_threshold = mean_entropy + 2 * std_entropy  # Adjust this threshold as needed
anomaly_days = daily_entropy[daily_entropy > anomaly_threshold]

print("\nDays with unusually high login randomness (potential anomalies):")
if not anomaly_days.empty:
    for date, entropy_value in anomaly_days.iteritems():
        print(f"{date}: {entropy_value}")
else:
    print("No days with unusually high login randomness were detected.")

# Plotting the entropy over time to visualize anomalies
plt.figure(figsize=(10, 6))
daily_entropy.plot(title='Daily Login Attempt Entropy')
plt.axhline(y=anomaly_threshold, color='r', linestyle='--', label='Anomaly Threshold')
plt.xlabel('Date')
plt.ylabel('Entropy')
plt.legend()
plt.tight_layout()
plt.savefig('daily_login_entropy.png')

df['hour'] = df['Generate Time'].dt.hour
login_attempts_by_hour = df.groupby('hour').size()
login_attempts_by_hour.plot(kind='bar', figsize=(10, 6), title='Login Attempts by Hour')
plt.xlabel('Hour of the Day')
plt.ylabel('Number of Attempts')
plt.tight_layout()
plt.savefig('login_attempts_by_hour.png')

# Analysis for unique usernames per IP and total attempts including srcregion
unique_usernames_per_ip = failed_logins_df.groupby('IP Address')['Username'].nunique().reset_index(name='Unique Username Count').sort_values(by='Unique Username Count', ascending=False)
print(f"\nTop 10 IPs by Unique Username Attempts:\n")
print(unique_usernames_per_ip.head(10).to_string(index=False))

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