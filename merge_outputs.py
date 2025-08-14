import os
from glob import glob

import pandas as pd

# Configuration
base_dir = '.'  # or set your base path explicitly
output_dirs = sorted(glob(os.path.join(base_dir, 'output*')))
output_file = 'merged_by_filename.xlsx'

# Find all unique CSV filenames across all output* folders
all_csv_files = []
for odir in output_dirs:
    all_csv_files.extend(glob(os.path.join(odir, '*.csv')))

# Extract just the file names (not full paths) and deduplicate
unique_csv_filenames = sorted(set(os.path.basename(f) for f in all_csv_files))

# Prepare Excel writer
writer = pd.ExcelWriter(output_file, engine='openpyxl')
MAX_EXCEL_ROWS = 1_048_576  # Excel worksheet row limit

for csv_name in unique_csv_filenames:
    matching_files = [os.path.join(odir, csv_name) for odir in output_dirs if os.path.exists(os.path.join(odir, csv_name))]
    
    dfs = []
    for file in matching_files:
        try:
            # Read all columns as strings to avoid dtype warnings
            df = pd.read_csv(file, dtype=str, low_memory=False)
            df['Exported_Logs'] = os.path.basename(os.path.dirname(file))  # record export directory
            dfs.append(df)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    if dfs:
        combined = pd.concat(dfs, ignore_index=True)

        # Drop duplicate rows to reduce sheet size
        combined.drop_duplicates(inplace=True)

        # Trim to Excel row limit if necessary
        if len(combined) > MAX_EXCEL_ROWS:
            # If "last_start_time" exists, retain the most recent rows
            if 'last_start_time' in combined.columns:
                combined['last_start_time'] = pd.to_datetime(
                    combined['last_start_time'], errors='coerce'
                )
                combined.sort_values('last_start_time', ascending=False, inplace=True)
                combined = combined.head(MAX_EXCEL_ROWS)
            else:
                combined = combined.head(MAX_EXCEL_ROWS)
            print(
                f"Trimmed {csv_name} to {MAX_EXCEL_ROWS} rows to fit Excel limits"
            )

        sheet_name = os.path.splitext(csv_name)[0][:31]  # Excel sheet name limit
        combined.to_excel(writer, sheet_name=sheet_name, index=False, header=True)
        print(f"Added sheet: {sheet_name} ({len(dfs)} files)")
    else:
        print(f"No data found for {csv_name}")

writer.close()
print(f"Workbook saved: {output_file}")
