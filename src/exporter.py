# src/exporter.py
import requests
import time
import os
import json

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
                    "ISSUE_SEVERITY_RANK", "ISSUE_SEVERITY", "SCORE", "PROBLEM_TITLE", "CVE", "CWE",
                    "PROJECT_NAME", "PROJECT_URL", "EXPLOIT_MATURITY", "FIRST_INTRODUCED",
                    "PRODUCT_NAME", "PROJECT_ORIGIN", "ISSUE_URL", "ISSUE_TYPE"
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

            org_dir = f"snyk_exports/{org_id}"
            os.makedirs(org_dir, exist_ok=True)

            for idx, result in enumerate(results):
                export_url = result.get("url")
                if export_url:
                    file_res = requests.get(export_url)
                    file_res.raise_for_status()
                    filename = f"{org_dir}/snyk_export_{org_id}_{export_id}_{idx + 1}.csv"
                    with open(filename, "wb") as f:
                        f.write(file_res.content)
                    logger.info(f"Saved: {filename}")
                else:
                    logger.warning("Missing export URL in result.")

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {org_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {org_id}: {e}")