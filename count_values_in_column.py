import pandas as pd

# Prompt the user to enter the CSV file path
csv_file_path = input("Enter the path to your CSV file: ")

try:
    # Load the CSV file
    df = pd.read_csv(csv_file_path)

    # Prompt the user to enter the column name
    column_name = input("Enter the column name you want to count values for: ")

    # Ensure the specified column exists in the DataFrame
    if column_name in df.columns:
        # Count the occurrences of each value in the specified column and print the result
        value_counts = df[column_name].value_counts()
        print(value_counts)
    else:
        print(f"The '{column_name}' column was not found in the CSV file.")
except FileNotFoundError:
    print("The specified CSV file was not found. Please check the file path.")
except Exception as e:
    print(f"An error occurred: {e}")