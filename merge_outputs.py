import os
from glob import glob
from collections import OrderedDict

import pandas as pd

# Expected reports mapping in insertion order
EXPECTED_REPORTS = OrderedDict([
    ("credential_success", "Summary of credential successes and failures"),
    ("device_ids", "List of unique device identifiers"),
    ("devices", "Detailed device information"),
    ("discovery_analysis", "Summary of discovery analysis results"),
    ("devices_with_cred", "Devices with associated credentials"),
    ("device", "Information for individual devices"),
    ("suggest_cred_opt", "Suggested credential optimizations"),
    ("schedules", "Discovery schedules"),
    ("overlapping_ips", "Overlapping IP ranges"),
])

def snake_to_title(value: str) -> str:
    """Convert snake_case strings to Title Case with spaces."""
    return " ".join(part.capitalize() for part in value.split("_"))

# Configuration
base_dir = "."
output_dirs = sorted(glob(os.path.join(base_dir, "output*")))
output_file = "merged_by_filename.xlsx"

# Find all unique CSV filenames across all output* folders
all_csv_files = []
for odir in output_dirs:
    all_csv_files.extend(glob(os.path.join(odir, "*.csv")))

# Extract just the file names (not full paths) and deduplicate
unique_csv_filenames = sorted(set(os.path.basename(f) for f in all_csv_files))

# Prepare Excel writer and tracking for merged reports
writer = pd.ExcelWriter(output_file, engine="openpyxl")
MAX_EXCEL_ROWS = 1_048_576  # Excel worksheet row limit
merged_reports = set()

for csv_name in unique_csv_filenames:
    matching_files = [
        os.path.join(odir, csv_name)
        for odir in output_dirs
        if os.path.exists(os.path.join(odir, csv_name))
    ]

    dfs = []
    for file in matching_files:
        try:
            # Read all columns as strings to avoid dtype warnings
            df = pd.read_csv(file, dtype=str, low_memory=False)
            df['Exported_Logs'] = os.path.basename(os.path.dirname(file))  # record export directory
            # Rename export column to a friendly format before concatenation
            df.rename(
                columns={'Exported_Logs': snake_to_title('Exported_Logs')},
                inplace=True,
            )
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
            if "last_start_time" in combined.columns:
                combined["last_start_time"] = pd.to_datetime(
                    combined["last_start_time"], errors="coerce"
                )
                combined.sort_values("last_start_time", ascending=False, inplace=True)
                combined = combined.head(MAX_EXCEL_ROWS)
            else:
                combined = combined.head(MAX_EXCEL_ROWS)
            print(
                f"Trimmed {csv_name} to {MAX_EXCEL_ROWS} rows to fit Excel limits",
            )

        sheet_name = snake_to_title(os.path.splitext(csv_name)[0])[:31]
        # Excel sheet names have a 31-character limit
        combined.to_excel(writer, sheet_name=sheet_name, index=False, header=True)
        print(f"Added sheet: {sheet_name} ({len(dfs)} files)")

        if sheet_name in EXPECTED_REPORTS:
            merged_reports.add(sheet_name)
    else:
        print(f"No data found for {csv_name}")

# Build cover sheet summarizing expected reports
records = []
for report, description in EXPECTED_REPORTS.items():
    row = {"report": report, "description": description}
    if report not in merged_reports:
        row["status"] = "missing—no corresponding CSV"
    records.append(row)

cover_df = pd.DataFrame(records, columns=["report", "description", "status"])
cover_df.to_excel(writer, sheet_name="Cover", index=False)

# Move cover sheet to the beginning
cover_sheet = writer.book["Cover"]
index = writer.book.worksheets.index(cover_sheet)
writer.book.move_sheet(cover_sheet, -index)

writer.close()
print(f"Workbook saved: {output_file}")
