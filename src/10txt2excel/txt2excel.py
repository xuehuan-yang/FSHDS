import os
import pandas as pd

# Define the folder path where your text files are located
# folder_path = '../50hds'
# folder_path = '../51wibe'
folder_path = '../53result/3pixel'

# Get a list of all text files in the folder
txt_files = [f for f in os.listdir(folder_path) if f.endswith('.txt')]

for txt_file in txt_files:
    # Construct the full file paths
    txt_file_path = os.path.join(folder_path, txt_file)
    excel_file_path = os.path.join(folder_path, os.path.splitext(txt_file)[0] + '.xlsx')

    # Read the text file into a pandas DataFrame
    df = pd.read_csv(txt_file_path, delim_whitespace=True, skipinitialspace=True)

    # Write the DataFrame to an Excel file
    df.to_excel(excel_file_path, index=False)

    print(f"Data from {txt_file_path} successfully converted and saved to {excel_file_path}")
