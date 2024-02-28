import pandas as pd

def clean_column_data(df, columns):
    for column in columns:
        if column in df.columns:
            # Ensure the column is of a string type
            if pd.api.types.is_string_dtype(df[column]):
                # Trim leading and trailing spaces
                df[column] = df[column].str.strip()
                # Convert text to lowercase
                df[column] = df[column].str.lower()
    return df

def export_results(duplicates, file_name, original_column_name):
    # Correctly rename the DataFrame columns for export
    duplicates = duplicates.reset_index().rename(columns={'index': original_column_name, 'count': 'Count'})
    # Export the duplicates DataFrame to a CSV file
    duplicates.to_csv(file_name, index=False)
    print(f"\nResults exported to {file_name}")

def check_for_duplicates(file_name, column_names, top_x_input, export, clean_data):
    try:
        # Load the CSV file into a DataFrame
        df = pd.read_csv(file_name)
        
        columns = column_names.split(',')
        columns = [column.strip() for column in columns]  # Remove any leading/trailing spaces from column names
        
        if clean_data:
            df = clean_column_data(df, columns)
        
        for column_name in columns:
            top_x = top_x_input  # Reset top_x to the user's original input for each column
            # Check if the column exists in the DataFrame
            if column_name not in df.columns:
                print(f"The column '{column_name}' does not exist in the file.")
                continue
            
            # Count the occurrences of each item in the specified column
            duplicates = df[column_name].value_counts()
            
            # Determine how many top items to display based on user input
            if top_x.lower() != 'all':
                try:
                    top_x = int(top_x)
                    duplicates = duplicates.head(top_x)
                except ValueError:
                    print("Invalid input. Please enter a number or the word 'all'.")
                    return
            
            # Print the count of each duplicate item in the top x or all
            print(f"\nColumn '{column_name}':")
            for item, count in duplicates.items():
                print(f"{item}: {count}")
            
            # Print the total number of unique items
            print(f"Total number of unique items in '{column_name}': {df[column_name].nunique()}")

            if export:
                export_file_name = f"{file_name.split('.')[0]}_{column_name}_duplicates.csv"
                export_results(duplicates, export_file_name, column_name)
    
    except FileNotFoundError:
        print(f"The file '{file_name}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def request_user_input(prompt):
    response = input(prompt).lower()
    while response not in ['yes', 'no', 'y', 'n']:
        response = input("Please enter 'yes' or 'no' (or 'y'/'n'): ").lower()
    return response in ['yes', 'y']

if __name__ == "__main__":
    file_name = input("Enter the file name: ")
    column_names = input("Enter the column name(s), separated by commas: ")
    top_x = input("Enter the number of top items to display, or 'all' for everything: ")
    clean_data = request_user_input("Do you want to clean the data in the requested column(s)? (yes/no): ")
    export = request_user_input("Do you want to export the results? (yes/no): ")
    check_for_duplicates(file_name, column_names, top_x, export, clean_data)
