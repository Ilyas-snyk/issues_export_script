import requests
import json
import os
import time
import logging
import sys  # Import the sys module for stdout

# --- Configuration ---
# Retrieve Snyk API token from environment variable
SNYK_API_TOKEN = os.environ.get("SNYK_API_TOKEN")
# Configuration file for organization IDs
CONFIG_FILE = "config.json"
# Log file configuration
LOG_FILE = "snyk_export.log"
LOG_LEVEL = logging.INFO  # You can change this to logging.DEBUG for more detailed logs

# --- End Configuration ---

# Configure logging
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),  # Log to file
        logging.StreamHandler(sys.stdout)  # Log to console
    ]
)

# API endpoint base URL template
base_url_template = "https://api.snyk.io/rest/orgs/{org_id}"
export_api_version = "version=2024-10-15"

# API endpoints
initiate_export_url_template = f"{base_url_template}/export?{export_api_version}"
status_url_template = f"{base_url_template}/jobs/export/{{export_id}}?{export_api_version}"
results_url_template = f"{base_url_template}/export/{{export_id}}?{export_api_version}"

# Request headers
headers = {
    "Content-Type": "application/json",
    "Authorization": f"token {SNYK_API_TOKEN}"
}

# Request body for initiating the export
export_payload = {
    "data": {
        "type": "resource",
        "attributes": {
            "formats": [
                "csv"
            ],
            "columns": [
                "ISSUE_SEVERITY_RANK",
                "ISSUE_SEVERITY",
                "SCORE",
                "PROBLEM_TITLE",
                "CVE",
                "CWE",
                "PROJECT_NAME",
                "PROJECT_URL",
                "EXPLOIT_MATURITY",
                "FIRST_INTRODUCED",
                "PRODUCT_NAME",
                "ISSUE_URL",
                "ISSUE_TYPE"
            ],
            "dataset": "issues",
            "destination": {
                "type": "snyk"
            },
            "filters": {
                "introduced": {
                    "from": "2025-01-30T00:00:00Z",
                    "to": "2025-04-01T00:00:00Z"
                }
            }
        }
    }
}

# Load organization IDs from the config file
ORG_IDS = []
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
        ORG_IDS = config.get("org_ids", [])
except FileNotFoundError:
    error_message = f"Error: {CONFIG_FILE} not found."
    logging.error(error_message)
except json.JSONDecodeError as e:
    error_message = f"Error: Invalid JSON in {CONFIG_FILE}: {e}"
    logging.error(error_message)

if not SNYK_API_TOKEN:
    error_message = "The SNYK_API_TOKEN environment variable is not set."
    logging.error(error_message)
elif not ORG_IDS:
    error_message = f"No organization IDs found in {CONFIG_FILE}."
    logging.warning(error_message)
else:
    for org_id in ORG_IDS:
        logging.info(f"--- Processing Organization: {org_id} ---")
        export_id = None
        try:
            # --- Step 1: Initiate Export ---
            initiate_url = initiate_export_url_template.format(org_id=org_id)
            logging.info("Initiating export...")
            initiate_response = requests.post(initiate_url, headers=headers, json=export_payload)
            initiate_response.raise_for_status()
            export_data = initiate_response.json()
            export_id = export_data.get("data", {}).get("id")

            if export_id:
                logging.info(f"Export initiated successfully. Export ID: {export_id}")

                # --- Step 2: Check Export Status ---
                status_url = status_url_template.format(org_id=org_id, export_id=export_id)
                logging.info("Checking export status...")
                while True:
                    status_response = requests.get(status_url, headers=headers)
                    status_response.raise_for_status()
                    status_data = status_response.json()
                    status = status_data.get("data", {}).get("attributes", {}).get("status")

                    if status == "FINISHED":
                        logging.info("Export finished successfully!")

                        # --- Step 3: Fetch Export Results ---
                        results_url = results_url_template.format(org_id=org_id, export_id=export_id)
                        logging.info("Fetching export results...")
                        try:
                            results_response = requests.get(results_url, headers=headers)
                            results_response.raise_for_status()
                            results_data = results_response.json()

                            # --- Safe Access and Iterate through 'results' List ---
                            results = results_data.get("data", {}).get("attributes", {}).get("results", [])
                            if results:  # Check if the 'results' list is not empty
                                # Create a directory for the organization if it doesn't exist
                                org_dir = f"snyk_exports/{org_id}"
                                if not os.path.exists(org_dir):
                                    os.makedirs(org_dir)
                                    logging.info(f"Created directory: {org_dir}")

                                for result in results:  # Iterate through each result
                                    export_url = result.get("url")
                                    if export_url:
                                        logging.info(f"Downloading from: {export_url}")
                                        try:
                                            # --- Download and save the file ---
                                            response = requests.get(export_url)
                                            response.raise_for_status()
                                            filename = f"{org_dir}/snyk_export_{org_id}_{export_id}_{results.index(result) + 1}.csv"  # Unique filename
                                            with open(filename, 'wb') as f:
                                                f.write(response.content)
                                            logging.info(f"Downloaded to: {filename}")
                                        except requests.exceptions.RequestException as e:
                                            error_message = f"Error downloading from {export_url}: {e}"
                                            logging.error(error_message)
                                    else:
                                        error_message = "Error: Export URL not found in API response."
                                        logging.error(error_message)
                            else:
                                error_message = "Error: No export results found in API response."
                                logging.error(error_message)

                        except requests.exceptions.RequestException as e:
                            error_message = f"Error fetching export results for {org_id}: {e}"
                            logging.error(error_message)
                            if results_response is not None:
                                logging.debug(f"Response status code: {results_response.status_code}")
                                logging.debug(f"Response body: {results_response.text}")
                        break
                    elif status == "ERROR":
                        error_message = f"Export failed for {org_id}. Error: {status_data.get('data', {}).get('attributes', {}).get('error')}"
                        logging.error(error_message)
                        break
                    elif status in ["PENDING", "STARTED"]:
                        logging.info(f"Export status for {org_id}: {status}. Checking again in 30 seconds...")
                        time.sleep(30)
                    else:
                        unexpected_status = f"Unexpected status for {org_id}: {status}. API Response: {json.dumps(status_data)}"
                        logging.warning(unexpected_status)
                        break
            else:
                error_message = f"Failed to initiate export for organization: {org_id}"
                logging.error(error_message)

        except requests.exceptions.RequestException as e:
            error_message = f"An error occurred while processing organization {org_id}: {e}"
            logging.error(error_message)
            if 'initiate_response' in locals() and initiate_response is not None:
                logging.debug(f"Initiate Response Status Code: {initiate_response.status_code}")
                logging.debug(f"Initiate Response Body: {initiate_response.text}")
            elif 'status_response' in locals() and status_response is not None:
                logging.debug(f"Status Response Status Code: {status_response.status_code}")
                logging.debug(f"Status Response Body: {status_response.text}")
