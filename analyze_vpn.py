import pandas as pd
import glob
import datetime
import matplotlib.pyplot as plt

def is_file_in_date_range(filename, start_date, end_date):
    """Check if the file's date falls within the specified date range."""
    file_date_str = filename.split('/')[-1].split('VPNAuthentications.csv')[0].split('-')[1]
    file_date = datetime.datetime.strptime(file_date_str, '%Y%m%d').date() - datetime.timedelta(days=1)
    return start_date <= file_date <= end_date

# Prompt for start and end dates
start_date_input = input("Enter the start date (YYYY-MM-DD): ")
end_date_input = input("Enter the end date (YYYY-MM-DD): ")

start_date = datetime.datetime.strptime(start_date_input, '%Y-%m-%d').date()
end_date = datetime.datetime.strptime(end_date_input, '%Y-%m-%d').date()

# Filter and load CSV files
all_files = glob.glob('VPNlogs/*.csv')
filtered_files = [file for file in all_files if is_file_in_date_range(file, start_date, end_date)]

df = pd.concat((pd.read_csv(f) for f in filtered_files), ignore_index=True)
df.rename(columns={'public_ip': 'IP Address', 'Source User': 'Username'}, inplace=True)

# Sorting by 'Generate Time' to ensure we use the most recent srcregion for each IP Address
df['Generate Time'] = pd.to_datetime(df['Generate Time'])
df.sort_values(by='Generate Time', inplace=True)

# Forward-fill srcregion for each IP Address to use the last known srcregion where possible
df['srcregion'] = df.groupby('IP Address')['srcregion'].ffill()

# If there are still NaN values after forward-fill, fill them with 'Unknown'
df['srcregion'].fillna('Unknown', inplace=True)

# Preparing the chart's date range label
date_range_label = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"

# Top 10 countries by login attempts analysis
login_attempts_by_country = df.groupby('srcregion').size().sort_values(ascending=False).head(10)
login_attempts_by_country.plot(kind='bar', figsize=(10, 6), title=f'Top 10 Login Attempts by Country ({date_range_label})')
plt.xlabel('Country')
plt.ylabel('Number of Login Attempts')
plt.tight_layout()
plt.savefig('top_10_login_attempts_by_country.png')

# Analyzing failed login attempts
failed_logins_df = df[df['status'] == 'failure']

# Unique usernames per IP Address analysis
unique_usernames_per_ip = failed_logins_df.groupby('IP Address')['Username'].nunique().reset_index(name='Unique Username Count').sort_values(by='Unique Username Count', ascending=False)
print(f"\nTop 10 IPs by Unique Username Attempts:\n")
print(unique_usernames_per_ip.head(10).to_string(index=False))

# Prepare data for the total number of attempts per IP address chart
failed_logins_with_country = failed_logins_df[['IP Address', 'srcregion']].drop_duplicates()

# Total number of attempts per IP address analysis
total_attempts_per_ip = failed_logins_df.groupby(['IP Address', 'srcregion']).size().reset_index(name='Total Attempts').sort_values(by='Total Attempts', ascending=False)
total_attempts_per_ip['IP Address'] = total_attempts_per_ip.apply(lambda x: f"{x['IP Address']} ({x['srcregion']})", axis=1)

# Plotting and saving the chart
plt.figure(figsize=(10, 6))
plt.barh(total_attempts_per_ip['IP Address'].head(10), total_attempts_per_ip['Total Attempts'].head(10))
plt.xlabel('Number of Failed Login Attempts')
plt.ylabel('IP Address')
plt.title(f'Top 10 IP Addresses by Failed Login Attempts ({date_range_label})')
plt.tight_layout()
plt.savefig('total_attempts_per_ip_with_country.png')

# Outputting the top 10 IPs by total number of attempts
print("\nTop 10 IPs by Total Number of Attempts:\n")
print(total_attempts_per_ip[['IP Address', 'Total Attempts']].head(10).to_string(index=False))
