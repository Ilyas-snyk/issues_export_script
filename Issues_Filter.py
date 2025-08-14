import os
import pandas as pd
import logging
import re
from dotenv import load_dotenv

def configure_logging(log_file, log_level):
    """Sets up logging configuration."""
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler() # Also print logs to console
        ]
    )

def filter_and_process_data(dataframes, filter_severities, filter_product, 
                            filter_issue_type, project_origin, org_id, 
                            filter_fixability=None):
    """
    Applies filters to a list of DataFrames and returns a single combined, filtered DataFrame.
    """
    all_filtered_data = []
    
    for df in dataframes:
        # Create a copy to avoid SettingWithCopyWarning
        df_copy = df.copy()

        # Check for required columns
        required_columns = {'ISSUE_SEVERITY', 'PRODUCT_NAME', 'ISSUE_TYPE', 'PROJECT_ORIGIN'}
        if not required_columns.issubset(df_copy.columns):
            missing = required_columns - set(df_copy.columns)
            logging.warning(f"[{org_id}] Skipping a DataFrame because it's missing columns: {missing}")
            continue

        # 1. Filter by severity, product, issue type, and project origin
        filtered_df = df_copy[
            df_copy['ISSUE_SEVERITY'].fillna('').str.lower().str.strip().isin(
                [sev.lower().strip() for sev in filter_severities]
            ) &
            (df_copy['PRODUCT_NAME'].fillna('').str.lower().str.strip() == filter_product.lower()) &
            (df_copy['ISSUE_TYPE'].fillna('').str.lower().str.strip() == filter_issue_type.lower()) &
            (df_copy['PROJECT_ORIGIN'].fillna('').str.lower().str.strip() == project_origin.lower())
        ]

        # 2. Filter only open issues
        if "ISSUE_STATUS" in filtered_df.columns:
            filtered_df = filtered_df[
                filtered_df["ISSUE_STATUS"].fillna("").str.lower().str.strip() == "open"
            ]
        else:
            logging.warning(f"[{org_id}] ISSUE_STATUS column not found. Skipping status filtering.")

        # 3. Apply COMPUTED_FIXABILITY filter if requested
        if filter_fixability:
            if "COMPUTED_FIXABILITY" in filtered_df.columns:
                filtered_df = filtered_df[
                    filtered_df['COMPUTED_FIXABILITY'].fillna('').str.lower().str.strip().isin(
                        [fix.lower().strip() for fix in filter_fixability]
                    )
                ]
            else:
                logging.warning(f"[{org_id}] COMPUTED_FIXABILITY column not found. Skipping fixability filtering.")

        if not filtered_df.empty:
            all_filtered_data.append(filtered_df)

    if not all_filtered_data:
        return pd.DataFrame() # Return empty DataFrame if no data matches

    # Combine all filtered dataframes from this filter set and return
    return pd.concat(all_filtered_data, ignore_index=True)


if __name__ == "__main__":
    load_dotenv()

    # --- Configuration ---
    BASE_EXPORT_DIR = os.environ.get("BASE_EXPORT_DIR", "./export")
    LOG_FILE = os.environ.get("LOG_FILE", "logs/snyk_filter_all.log")
    PROJECT_ORIGIN = os.environ.get("PROJECT_ORIGIN", "github-enterprise")
    ORIGINAL_FILE_PATTERN = r"^snyk_export_[a-zA-Z0-9_\- ]+_[a-zA-Z0-9_\- ]+_\d+\.csv$"
    LOG_LEVEL = logging.INFO
    
    configure_logging(LOG_FILE, LOG_LEVEL)

    if not os.path.exists(BASE_EXPORT_DIR):
        logging.error(f"Base export directory not found: {BASE_EXPORT_DIR}")
        exit()

    # --- Main Processing Loop ---
    org_dirs = [d for d in os.listdir(BASE_EXPORT_DIR) if os.path.isdir(os.path.join(BASE_EXPORT_DIR, d))]
    logging.info(f"Found {len(org_dirs)} organization folders to process.")

    for org_id in org_dirs:
        org_path = os.path.join(BASE_EXPORT_DIR, org_id)
        logging.info(f"--- Processing Organization: {org_id} ---")

        # 1. Read all relevant CSVs for the organization into memory once
        source_files = [f for f in os.listdir(org_path) if re.match(ORIGINAL_FILE_PATTERN, f, re.IGNORECASE)]
        if not source_files:
            logging.warning(f"[{org_id}] No matching source CSVs found. Skipping.")
            continue
        
        logging.info(f"[{org_id}] Found {len(source_files)} source files to process.")

        # Extract org name from the first matching filename
        org_name_match = re.match(
            r"^snyk_export_(?P<org_name>[a-zA-Z0-9_\- ]+)_([a-zA-Z0-9_\- ]+)_\d+\.csv$",
            source_files[0],
            re.IGNORECASE
        )
        if org_name_match:
            org_name = org_name_match.group("org_name")
        else:
            logging.warning(f"[{org_id}] Could not extract org name from filename, using org ID instead.")
            org_name = org_id
        
        org_dataframes = []
        for file in source_files:
            try:
                filepath = os.path.join(org_path, file)
                df = pd.read_csv(filepath)
                org_dataframes.append(df)
            except Exception as e:
                logging.error(f"[{org_id}] Failed to read file {file}: {e}")

        if not org_dataframes:
            logging.warning(f"[{org_id}] Could not read any dataframes. Skipping.")
            continue

        # 2. Apply each filter set and collect the results
        all_results_for_org = []

        # Filter 1: Open Source Vulnerabilities (Fixable)
        logging.info(f"[{org_id}] Applying filter: Open Source Critical/High Fixable Vulns")
        df1 = filter_and_process_data(
            org_dataframes,
            filter_severities=['high', 'critical'],
            filter_product="Snyk Open Source",
            filter_issue_type="vulnerability",
            project_origin=PROJECT_ORIGIN,
            org_id=org_id,
            filter_fixability=["Fixable", "Partially Fixable"]
        )
        if not df1.empty:
            all_results_for_org.append(df1)
        
        # Filter 2: License Issues
        logging.info(f"[{org_id}] Applying filter: Open Source High Severity Licenses")
        df2 = filter_and_process_data(
            org_dataframes,
            filter_severities=['high'],
            filter_product="Snyk Open Source",
            filter_issue_type="license",
            project_origin=PROJECT_ORIGIN,
            org_id=org_id
        )
        if not df2.empty:
            all_results_for_org.append(df2)

        # Filter 3: Snyk Code Vulnerabilities
        logging.info(f"[{org_id}] Applying filter: Snyk Code High Vulns")
        df3 = filter_and_process_data(
            org_dataframes,
            filter_severities=['high'],
            filter_product="Snyk Code",
            filter_issue_type="vulnerability",
            project_origin=PROJECT_ORIGIN,
            org_id=org_id
        )
        if not df3.empty:
            all_results_for_org.append(df3)

        # 3. Combine, deduplicate, and save the final single CSV
        if all_results_for_org:
            final_df = pd.concat(all_results_for_org, ignore_index=True)
            
            # Deduplicate across the entire combined dataset
            before_dedup = len(final_df)
            final_df.drop_duplicates(inplace=True)
            after_dedup = len(final_df)
            logging.info(f"[{org_id}] Combined all filtered results. Total rows: {after_dedup} (Removed {before_dedup - after_dedup} duplicates).")

            # Define output path using org name instead of org ID
            output_subfolder = "filtered_results_code_sca"
            combined_filename = f"{org_name}_snyk_filtered_results.csv"
            output_path = os.path.join(BASE_EXPORT_DIR, org_name, output_subfolder)
            os.makedirs(output_path, exist_ok=True)
            output_file = os.path.join(output_path, combined_filename)

            try:
                final_df.to_csv(output_file, index=False, encoding='utf-8')
                logging.info(f"[{org_id}] SUCCESS: Saved combined results to {output_file}")
            except Exception as e:
                logging.error(f"[{org_id}] FAILED to save combined file {output_file}: {e}")
        else:
            logging.warning(f"[{org_id}] No data matched any of the specified filters. No output file will be created.")

    logging.info("=== Snyk Filtering Complete ===")
