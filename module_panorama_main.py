import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime, timedelta
from module_database import create_connection
from module_utility import get_validated_input, get_datetime_range, validate_datetime
from module_globalprotect_analysis import fetch_event_sequence, analyze_event_sequences, print_daily_status_summary
from module_threat_analysis import threat_analysis, fetch_threat_counts_by_day, get_user_confirmation
from module_statistical_analysis import fetch_failed_logins, perform_statistical_analysis
from module_entropy_analysis import fetch_login_data, calculate_entropy, identify_anomalies
from dotenv import load_dotenv
import os

load_dotenv()

class PDFReport(FPDF):
    def __init__(self, start_date, end_date):
        super().__init__()
        self.start_date = start_date
        self.end_date = end_date
        self.alias_nb_pages()

    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, f'Panorama Analysis Report - {self.start_date} to {self.end_date}', 0, 1, 'L')
        # Add the logo to the top right corner
        self.image('organization_logo.png', x=170, y=10, w=30)
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'R')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(0, 0, 0)  # Set text color to black
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.set_text_color(0, 0, 0)  # Set text color to black
        if body:  # Check if body is not None
            self.multi_cell(0, 10, body)
        self.ln()

    def add_image(self, image_path, x=None, y=None, w=0, h=0):
        self.image(image_path, x=x, y=y, w=w, h=h)

    def add_table(self, data, col_widths):
        self.set_font('Arial', 'B', 12)
        for header in data.columns:
            self.cell(col_widths[header], 10, header, 1, 0, 'C')
        self.ln()

        self.set_font('Arial', '', 12)
        for index, row in data.iterrows():
            for col in data.columns:
                self.cell(col_widths[col], 10, str(row[col]), 1, 0, 'C')
            self.ln()
        self.ln()

def create_bar_chart(data, title, x_label, y_label, output_file, threshold=None):
    plt.figure(figsize=(10, 5))
    plt.bar(data.keys(), data.values(), color='skyblue')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.xticks(rotation=45, ha='right')
    if threshold is not None:
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.2f})')
        plt.legend()
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

def create_stacked_bar_chart(df, title, output_file):
    df.plot(kind='bar', stacked=True, figsize=(10, 5))
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

def print_and_append(pdf, message, to_terminal=True):
    if to_terminal:
        print(message)
    pdf.chapter_body(message)

def main():
    conn = create_connection("panorama_logs.db")
    if conn:
        now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y/%m/%d %H:%M:%S")
        start_datetime_input = get_validated_input('Enter start date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, yesterday)
        end_datetime_input = get_validated_input('Enter end date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, now)
        
        exclude_own_ips = get_user_confirmation('Do you want to exclude threats from IPs in the ' + os.getenv('ORG_IP_PREFIX') + '.*.* range? (yes/no): ')
        
        start_datetime, end_datetime = get_datetime_range(start_datetime_input, end_datetime_input)

        pdf = PDFReport(start_datetime_input, end_datetime_input)
        pdf.add_page()

        # GlobalProtect Analysis
        pdf.chapter_title('GlobalProtect Analysis')
        events = fetch_event_sequence(conn, start_datetime, end_datetime)
        alerts = analyze_event_sequences(events)
        if alerts:
            alert_msg = "\nHeads-up! Found IPs with a failed 'portal-auth' followed by a successful 'gateway-auth':"
            for alert in alerts:
                alert_msg += f"\nIP: {alert[0]}, Failed portal-auth at {alert[1]}, Successful gateway-auth at {alert[2]}"
            print_and_append(pdf, alert_msg)
        else:
            alert_msg = "\nNo instances found of an IP with a failed 'portal-auth' followed by a successful 'gateway-auth'."
            print_and_append(pdf, alert_msg)

        daily_status_summary = print_daily_status_summary(conn, start_datetime, end_datetime)
        print_and_append(pdf, daily_status_summary)

        #  Daily Status Summary Chart
        daily_status_df = pd.read_sql_query("""
            SELECT strftime('%Y-%m-%d', datetime(substr(Time_Generated, 1, 4) || '-' || 
                                                  substr(Time_Generated, 6, 2) || '-' || 
                                                  substr(Time_Generated, 9, 2) || ' ' || 
                                                  substr(Time_Generated, 12))) AS Date, 
                   Status, COUNT(*) AS Count
            FROM GlobalProtectLogs
            WHERE datetime(substr(Time_Generated, 1, 4) || '-' || 
                          substr(Time_Generated, 6, 2) || '-' || 
                          substr(Time_Generated, 9, 2) || ' ' || 
                          substr(Time_Generated, 12)) >= datetime(?)
            AND datetime(substr(Time_Generated, 1, 4) || '-' || 
                        substr(Time_Generated, 6, 2) || '-' || 
                        substr(Time_Generated, 9, 2) || ' ' || 
                        substr(Time_Generated, 12)) <= datetime(?)
            GROUP BY Date, Status
            ORDER BY Date, Status DESC;
        """, conn, params=[start_datetime.strftime("%Y-%m-%d %H:%M:%S"), end_datetime.strftime("%Y-%m-%d %H:%M:%S")])

        if not daily_status_df.empty:
            daily_status_pivot = daily_status_df.pivot(index='Date', columns='Status', values='Count').fillna(0)
            create_stacked_bar_chart(daily_status_pivot, "Daily Status Summary", "daily_status_chart.png")
            pdf.add_image("daily_status_chart.png", w=180)

        # Statistical Analysis
        pdf.chapter_title('Statistical Analysis')
        failed_logins = fetch_failed_logins(conn, start_datetime, end_datetime)
        if failed_logins:
            outlier_summary = perform_statistical_analysis(failed_logins)
            if not outlier_summary.empty:
                top_outliers = outlier_summary.head(10)  # Limit to top 10 outliers
                stat_msg = "\nTop 10 IPs with unusual number of login attempts (Outliers), their country codes, and Z-scores:"
                for index, row in top_outliers.iterrows():
                    stat_msg += f"\n{row['IP_Address']} ({row['Source_Region']}): {row['Total Attempts']} attempts (Z-score: {row['z_score']:.2f})"
                print_and_append(pdf, stat_msg)
                # Create bar chart for top 10 outliers
                outliers_dict = top_outliers.set_index('IP_Address')['Total Attempts'].to_dict()
                create_bar_chart(outliers_dict, "Top 10 Outliers by Total Attempts", "IP Address", "Total Attempts", "outliers_chart.png")
                pdf.add_image("outliers_chart.png", w=180)
            else:
                print_and_append(pdf, "\nNo outliers found based on Z-score analysis.")
        else:
            print_and_append(pdf, "\nNo failed login attempts found within the specified range.")

        # Entropy Analysis
        pdf.chapter_title('Entropy Analysis')
        login_data = fetch_login_data(conn, start_datetime, end_datetime)
        if login_data:
            df = pd.DataFrame(login_data, columns=['date', 'IP_Address'])
            daily_entropy = calculate_entropy(df)
            anomaly_days, threshold = identify_anomalies(daily_entropy)
            
            entropy_msg = "\nDays with unusually high entropy (anomalies):"
            if not anomaly_days.empty:
                for date, entropy_value in anomaly_days.iteritems():
                    entropy_msg += f"\nDate: {date}, Entropy: {entropy_value:.2f}"
                print_and_append(pdf, entropy_msg)
            else:
                print_and_append(pdf, "\nNo anomalies found based on entropy analysis.")
            
            # Create bar chart for daily entropy values with threshold
            create_bar_chart(daily_entropy.to_dict(), "Daily Entropy Values", "Date", "Entropy", "entropy_chart.png", threshold=threshold)
            pdf.add_image("entropy_chart.png", w=180)
        else:
            print_and_append(pdf, "\nNo login data found within the specified range.")

        # Threat Analysis
        pdf.chapter_title('Threat Analysis')
        threat_output = threat_analysis(conn, start_datetime, end_datetime, exclude_own_ips)
        print_and_append(pdf, threat_output)

        # Add Threat Counts by Day Chart
        pdf.chapter_title('Daily Count of Threats')
        threat_counts_by_day = fetch_threat_counts_by_day(conn, start_datetime, end_datetime)
        if not threat_counts_by_day.empty:
            threat_counts_by_day_dict = threat_counts_by_day['Count'].to_dict()
            create_bar_chart(threat_counts_by_day_dict, "Threat Counts by Day", "Date", "Count", "threat_counts_chart.png")
            pdf.add_image("threat_counts_chart.png", w=180)

        conn.close()

        pdf.output("analysis_report.pdf")

    else:
        print("Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()