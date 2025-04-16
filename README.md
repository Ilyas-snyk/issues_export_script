# api-export
📦 Snyk Issues Export Script
This script automates the export of issue data from the Snyk REST API for one or more organizations. It exports issue reports as CSV files and saves them locally for further analysis.

🔧 Features
Supports exporting from multiple Snyk organizations using a config file

Fetches issue data within a specific time window

Saves CSV export files to a structured local directory

Includes logging to both file and console for visibility

Uses the Snyk REST API (not the legacy API)

📁 Directory Structure
After running, the output will look like:

python
Copy
Edit
snyk_exports/
├── org-1-id/
│   ├── snyk_export_org-1-id_exportid_1.csv
│   └── ...
├── org-2-id/
│   └── snyk_export_org-2-id_exportid_1.csv
📋 Prerequisites
Python 3.7+

A valid Snyk API token

Your organization IDs

📂 Configuration
Set the Snyk API Token as an environment variable:

bash
Copy
Edit
export SNYK_API_TOKEN=your-token-here
Create a config.json file in the same directory:

json
Copy
Edit
{
  "org_ids": [
    "org-1-id",
    "org-2-id"
  ]
}
🚀 Running the Script
bash
Copy
Edit
python snyk_export.py
🧾 Logging
Logs to snyk_export.log

Also logs to the console (stdout)

You can change the log level by modifying LOG_LEVEL in the script:

python
Copy
Edit
LOG_LEVEL = logging.DEBUG  # For verbose logs
⚙️ Customization
The script uses fixed filters:

Introduced date range: 2025-01-30 to 2025-04-01

Dataset: issues

Format: csv

Columns: (e.g., CVE, CWE, PROJECT_NAME, etc.)

To change these, edit the export_payload section of the script.
