import pandas as pd
from datetime import datetime, timedelta
from module_database import create_connection
from module_utility import get_validated_input, get_datetime_range, validate_datetime, get_user_confirmation
from module_globalprotect_analysis import fetch_event_sequence, analyze_event_sequences, print_daily_status_summary
from module_threat_analysis import threat_analysis, fetch_threat_counts_by_day
from module_statistical_analysis import fetch_failed_logins, perform_statistical_analysis
from module_entropy_analysis import fetch_login_data, calculate_entropy, identify_anomalies, fetch_all_login_data, calculate_hourly_entropy
from module_known_offenders import process_known_offenders
from module_pdf_report import PDFReport, print_and_append
from module_chart_creation import create_bar_chart, create_stacked_bar_chart, create_entropy_heatmap
from dotenv import load_dotenv
import os
import logging
from typing import List, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

def main():
    conn = create_connection("panorama_logs.db")
    if conn:
        now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y/%m/%d %H:%M:%S")
        start_datetime_input = get_validated_input('Enter start date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, yesterday)
        end_datetime_input = get_validated_input('Enter end date/time (YYYY/MM/DD HH:MM:SS), or leave blank: ', validate_datetime, now)
        
        exclude_own_ips = get_user_confirmation('Do you want to exclude threats from IPs in the ' + os.getenv('ORG_IP_PREFIX') + '.*.* range? (yes/no): ', default='yes')
        
        start_datetime, end_datetime = get_datetime_range(start_datetime_input, end_datetime_input)

        pdf = PDFReport(start_datetime_input, end_datetime_input)
        pdf.add_page()

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

        pdf.chapter_title('Statistical Analysis')
        failed_logins = fetch_failed_logins(conn, start_datetime, end_datetime)
        if failed_logins:
            outlier_summary = perform_statistical_analysis(failed_logins)
            if not outlier_summary.empty:
                top_outliers = outlier_summary.head(10)
                stat_msg = "\nTop 10 IPs with unusual number of login attempts (Outliers), their country codes, and Z-scores:"
                for index, row in top_outliers.iterrows():
                    stat_msg += f"\n{row['IP_Address']} ({row['Source_Region']}): {row['Total Attempts']} attempts (Z-score: {row['z_score']:.2f})"
                print_and_append(pdf, stat_msg)
                outliers_dict = top_outliers.set_index('IP_Address')['Total Attempts'].to_dict()
                create_bar_chart(outliers_dict, "Top 10 Outliers by Total Attempts", "IP Address", "Total Attempts", "outliers_chart.png")
                pdf.add_image("outliers_chart.png", w=180)
            else:
                print_and_append(pdf, "\nNo outliers found based on Z-score analysis.")
        else:
            print_and_append(pdf, "\nNo failed login attempts found within the specified range.")

        pdf.chapter_title('Entropy Analysis')
        login_data = fetch_login_data(conn, start_datetime, end_datetime)
        if login_data:
            df = pd.DataFrame(login_data, columns=['date', 'IP_Address'])
            daily_entropy = calculate_entropy(df)
            anomaly_days, threshold = identify_anomalies(daily_entropy)
            
            entropy_msg = "\nDays with unusually high entropy (anomalies):"
            if not anomaly_days.empty:
                for date, entropy_value in anomaly_days.items():
                    entropy_msg += f"\nDate: {date}, Entropy: {entropy_value:.2f}"
                print_and_append(pdf, entropy_msg)
            else:
                print_and_append(pdf, "\nNo anomalies found based on entropy analysis.")
            
            create_bar_chart(daily_entropy.to_dict(), "Daily Entropy Values", "Date", "Entropy", "entropy_chart.png", threshold=threshold)
            pdf.add_image("entropy_chart.png", w=180)
        else:
            print_and_append(pdf, "\nNo login data found within the specified range.")

        pdf.chapter_title('Entropy Heatmap')
        all_login_data = fetch_all_login_data(conn, start_datetime, end_datetime)
        if all_login_data:
            df_all = pd.DataFrame(all_login_data, columns=['Time_Generated', 'IP_Address', 'Source_Region', 'Source_User'])
            entropy_df = calculate_hourly_entropy(df_all)
            heatmap_output_file = f'entropy_heatmap.png'
            create_entropy_heatmap(entropy_df, start_datetime_input, end_datetime_input, heatmap_output_file)
            pdf.add_image(heatmap_output_file, w=180)
        else:
            print_and_append(pdf, "\nNo login data found for heatmap within the specified range.")

        pdf.chapter_title('Threat Analysis')
        threat_output = threat_analysis(conn, start_datetime, end_datetime, exclude_own_ips)
        print_and_append(pdf, threat_output)

        pdf.chapter_title('Daily Count of Threats')
        threat_counts_by_day = fetch_threat_counts_by_day(conn, start_datetime, end_datetime)
        if not threat_counts_by_day.empty:
            threat_counts_by_day_dict = threat_counts_by_day['Count'].to_dict()
            create_bar_chart(threat_counts_by_day_dict, "Threat Counts by Day", "Date", "Count", "threat_counts_chart.png")
            pdf.add_image("threat_counts_chart.png", w=180)

        pdf.ln(10) 
        pdf.chapter_title('Known Offenders Analysis')

        bad_ips_file = 'bad_ips.txt'
        bad_ips_results = process_known_offenders("panorama_logs.db", bad_ips_file, start_datetime_input, end_datetime_input)

        if bad_ips_results:
            bad_ips_msg = "\nKnown Bad IPs found in logs:"
            seen_bad_ips = set()
            for result in bad_ips_results:
                if result not in seen_bad_ips:
                    seen_bad_ips.add(result)
                    table_name, first_seen, last_seen, count, ip_addresses, destination_ips, source_regions = result
                    if table_name == 'ThreatLogs':
                        bad_ips_msg += f"\nTable: {table_name}, First Seen: {first_seen}, Last Seen: {last_seen}, Count: {count}, IPs: {ip_addresses}, Dest. IPs: {destination_ips}, Regions: {source_regions}"
                    elif table_name == 'GlobalProtectLogs':
                        bad_ips_msg += f"\nTable: {table_name}, First Seen: {first_seen}, Last Seen: {last_seen}, Count: {count}, IPs: {ip_addresses}, Users: {destination_ips}, Regions: {source_regions}"
            print_and_append(pdf, bad_ips_msg, to_terminal=True)
        else:
            print_and_append(pdf, "\nNo bad IPs found within the specified range.", to_terminal=True)

        conn.close()

        pdf.output("analysis_report.pdf")
        logger.info("Analysis report generated successfully.")

    else:
        logger.error("Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()