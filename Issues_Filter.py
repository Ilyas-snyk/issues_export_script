import os
import pandas as pd
import logging
import re
from dotenv import load_dotenv

def configure_logging(log_file, log_level):
    logging.basicConfig(filename=log_file, level=log_level,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def process_organization(org_path, original_file_pattern, filter_severities, filter_product,
                         filter_issue_type, output_subfolder, combined_filename, org_id,
                         project_origin, filter_fixability=None):
    """Processes and filters CSVs for a single filter type, returns one combined CSV per org."""
    original_files = [f for f in os.listdir(org_path) if re.match(original_file_pattern, f)]
    logging.info(f"[{org_id}] Found files: {original_files}")

    if not original_files:
        logging.info(f"[{org_id}] No matching CSVs found. Skipping.")
        return

    all_filtered_data = []
    for original_file in original_files:
        original_filepath = os.path.join(org_path, original_file)
        try:
            df = pd.read_csv(original_filepath)
            logging.debug(f"[{org_id}] Columns in {original_file}: {df.columns.tolist()}")

            required_columns = {'ISSUE_SEVERITY', 'PRODUCT_NAME', 'ISSUE_TYPE', 'PROJECT_ORIGIN'}
            missing = required_columns - set(df.columns)
            if missing:
                logging.warning(f"[{org_id}] Missing columns {missing} in {original_file}. Skipping.")
                continue

            # Filter by severity, product, issue type, and project origin
            filtered_df = df[
                df['ISSUE_SEVERITY'].fillna('').str.lower().str.strip().isin(
                    [sev.lower().strip() for sev in filter_severities]
                ) &
                (df['PRODUCT_NAME'].fillna('').str.lower().str.strip() == filter_product.lower()) &
                (df['ISSUE_TYPE'].fillna('').str.lower().str.strip() == filter_issue_type) &
                (df['PROJECT_ORIGIN'].fillna('').str.lower().str.strip() == project_origin.lower())
            ]

            # Apply COMPUTED_FIXABILITY filter if requested
            if filter_fixability:
                if "COMPUTED_FIXABILITY" not in filtered_df.columns:
                    logging.warning(f"[{org_id}] COMPUTED_FIXABILITY column not found in {original_file}. Skipping fixability filtering.")
                else:
                    filtered_df = filtered_df[
                        filtered_df['COMPUTED_FIXABILITY'].fillna('').str.lower().str.strip().isin(
                            [fix.lower().strip() for fix in filter_fixability]
                        )
                    ]

            if not filtered_df.empty:
                all_filtered_data.append(filtered_df)

        except Exception as e:
            logging.error(f"[{org_id}] Error processing file {original_file}: {e}")

    if all_filtered_data:
        combined_df = pd.concat(all_filtered_data, ignore_index=True)
        output_path = os.path.join(org_path, output_subfolder)
        os.makedirs(output_path, exist_ok=True)
        output_file = os.path.join(output_path, combined_filename)

        try:
            combined_df.to_csv(output_file, index=False, encoding='utf-8')
            logging.info(f"[{org_id}] Saved combined: {output_file}")
        except Exception as e:
            logging.error(f"[{org_id}] Failed to save {output_file}: {e}")
    else:
        logging.info(f"[{org_id}] No data matched for {filter_product} / {filter_issue_type}.")

if __name__ == "__main__":
    load_dotenv()

    BASE_EXPORT_DIR = os.environ.get("BASE_EXPORT_DIR", "")
    LOG_FILE = os.environ.get("LOG_FILE", "snyk_filter_all.log")
    PROJECT_ORIGIN = os.environ.get("PROJECT_ORIGIN", "github-enterprise")
    ORIGINAL_FILE_PATTERN = r"^snyk_export_[a-f0-9-]+_[a-f0-9-]+_\d+\.csv$"
    LOG_LEVEL = logging.INFO

    # Ensure logs directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    configure_logging(LOG_FILE, LOG_LEVEL)

    if not os.path.exists(BASE_EXPORT_DIR):
        logging.error(f"Base export directory not found: {BASE_EXPORT_DIR}")
        exit()

    org_dirs = [d for d in os.listdir(BASE_EXPORT_DIR)
                if os.path.isdir(os.path.join(BASE_EXPORT_DIR, d))]

    logging.info(f"Found {len(org_dirs)} orgs: {org_dirs}")

    for org_id in org_dirs:
        org_path = os.path.join(BASE_EXPORT_DIR, org_id)

        # 1. Open Source Vulnerabilities with fixability filter
        process_organization(
            org_path,
            ORIGINAL_FILE_PATTERN,
            ['high', 'critical'],
            "Snyk Open Source",
            "vulnerability",
            "filtered_open_source",
            "Snyk Open Source Critical and High Vulns.csv",
            org_id,
            PROJECT_ORIGIN,
            filter_fixability=["Fixable", "Partially Fixable"]
        )

        # 2. License Issues (no fixability filter)
        process_organization(
            org_path,
            ORIGINAL_FILE_PATTERN,
            ['high'],
            "Snyk Open Source",
            "license",
            "filtered_license_issues",
            "Snyk Open Source High Severity Licenses.csv",
            org_id,
            PROJECT_ORIGIN
        )

        # 3. Snyk Code Vulnerabilities (no fixability filter)
        process_organization(
            org_path,
            ORIGINAL_FILE_PATTERN,
            ['high'],
            "Snyk Code",
            "vulnerability",
            "filtered_code_vulns",
            "Snyk Code High Vulns.csv",
            org_id,
            PROJECT_ORIGIN
        )

    logging.info("=== Snyk Filtering Complete ===")
