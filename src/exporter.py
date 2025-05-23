# src/exporter.py
import requests
import time
import os
import json
import csv
import re

def sanitize_name(name: str) -> str:
    # Remove or replace characters not safe for folder/file names
    return re.sub(r'[^a-zA-Z0-9_\- ]+', '_', name).strip()

def run_exports(org_ids, token, logger):
    base_url_template = "https://api.snyk.io/rest/orgs/{org_id}"
    export_api_version = "version=2024-10-15"

    initiate_export_url_template = f"{base_url_template}/export?{export_api_version}"
    status_url_template = f"{base_url_template}/jobs/export/{{export_id}}?{export_api_version}"
    results_url_template = f"{base_url_template}/export/{{export_id}}?{export_api_version}"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"token {token}"
    }

    export_payload = {
        "data": {
            "type": "resource",
            "attributes": {
                "formats": ["csv"],
                "columns": [
                    "PROBLEM_ID", "PRODUCT_NAME", "PROBLEM_TITLE", "VULN_DB_URL", "ISSUE_TYPE",
                    "ISSUE_URL", "ISSUE_STATUS", "ISSUE_SEVERITY", "SCORE", "CVE", "CWE", "PROJECT_ORIGIN",
                    "EXPLOIT_MATURITY", "INTRODUCTION_CATEGORY", "SNYK_CVSS_SCORE", "SNYK_CVSS_VECTOR",
                    "COMPUTED_FIXABILITY","FIXED_IN_AVAILABLE", "FIXED_IN_VERSION", "PACKAGE_NAME_AND_VERSION",
                    "FIRST_INTRODUCED", "LAST_INTRODUCED", "LAST_IGNORED","LAST_RESOLVED", "REACHABILITY","ORG_DISPLAY_NAME"
                ],
                "dataset": "issues",
                "destination": { "type": "snyk" },
                "filters": {
                    "introduced": {
                        "from": "2025-01-30T00:00:00Z",
                        "to": "2025-04-01T00:00:00Z"
                    }
                }
            }
        }
    }

    base_dir = os.path.abspath("snyk_exports")
    os.makedirs(base_dir, exist_ok=True)

    for org_id in org_ids:
        logger.info(f"--- Processing Organization: {org_id} ---")
        try:
            # Step 1: Initiate Export
            initiate_url = initiate_export_url_template.format(org_id=org_id)
            res = requests.post(initiate_url, headers=headers, json=export_payload)
            res.raise_for_status()
            export_id = res.json().get("data", {}).get("id")

            if not export_id:
                logger.error(f"Failed to initiate export for {org_id}")
                continue

            logger.info(f"Export initiated: {export_id}")

            # Step 2: Poll for Export Status
            while True:
                status_url = status_url_template.format(org_id=org_id, export_id=export_id)
                status_res = requests.get(status_url, headers=headers)
                status_res.raise_for_status()
                status = status_res.json().get("data", {}).get("attributes", {}).get("status")

                if status == "FINISHED":
                    logger.info("Export finished.")
                    break
                elif status == "ERROR":
                    error = status_res.json().get("data", {}).get("attributes", {}).get("error")
                    logger.error(f"Export failed: {error}")
                    break
                else:
                    logger.info(f"Status: {status}. Waiting 30 seconds...")
                    time.sleep(30)

            # Step 3: Fetch Results
            results_url = results_url_template.format(org_id=org_id, export_id=export_id)
            results_res = requests.get(results_url, headers=headers)
            results_res.raise_for_status()
            results = results_res.json().get("data", {}).get("attributes", {}).get("results", [])

            if not results:
                logger.warning("No export results found.")
                continue

            for idx, result in enumerate(results):
                export_url = result.get("url")
                if export_url:
                    file_res = requests.get(export_url)
                    file_res.raise_for_status()

                    csv_content = file_res.content.decode('utf-8')

                    reader = csv.DictReader(csv_content.splitlines())
                    first_row = next(reader, None)

                    if first_row:
                        logger.debug(f"CSV columns: {list(first_row.keys())}")
                        # Case-insensitive lookup of ORG_DISPLAY_NAME
                        header_map = {k.lower(): k for k in first_row.keys()}
                        org_display_key = header_map.get('org_display_name')
                        if org_display_key:
                            raw_org_name = first_row[org_display_key]
                            logger.debug(f"Extracted ORG_DISPLAY_NAME: {raw_org_name}")
                            safe_org_name = sanitize_name(raw_org_name)
                        else:
                            logger.warning("ORG_DISPLAY_NAME column not found, using org_id instead.")
                            safe_org_name = sanitize_name(org_id)
                    else:
                        logger.warning("No rows in CSV, using org_id as folder name.")
                        safe_org_name = sanitize_name(org_id)

                    # Construct full safe paths
                    org_dir = os.path.join(base_dir, safe_org_name)
                    os.makedirs(org_dir, exist_ok=True)

                    filename = os.path.join(org_dir, f"snyk_export_{safe_org_name}_{export_id}_{idx + 1}.csv")
                    abs_path = os.path.abspath(filename)

                    # Security check to prevent path traversal
                    if not abs_path.startswith(base_dir + os.sep):
                        logger.error(f"Unsafe file path detected: {abs_path}")
                        continue  # Skip saving this file

                    # Write the file to the full safe path (fix here)
                    with open(abs_path, "wb") as f:
                        f.write(file_res.content)

                    logger.info(f"Saved: {abs_path}")
                else:
                    logger.warning("Missing export URL in result.")

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {org_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {org_id}: {e}")
