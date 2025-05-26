# Issues Export Script

This repository contains Python scripts designed to fetch, filter, and organize Snyk vulnerability and license issue data. It supports both direct CSV export filtering and automated API-based export across multiple organizations, allowing you to filter by severity, issue type, product, origin, and introduction date.

## Prerequisites

Before running the scripts, make sure you have:

- Python 3.x installed on your machine.
- `pip` for installing Python dependencies.
- Snyk API token
- Snyk org IDs



### Required Python Libraries

To install the required dependencies, run the following command in your terminal:

```bash
pip install -r requirements.txt
```

This will install:

- `pandas`: Used for data processing and manipulation.
- `python-dotenv`: Helps load environment variables from the `.env` file.
- `requests`: Helps with API communication

## Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/ilyas-snyk/Issues_Export_Script.git
   cd Issues_Export_Script
   ```

2. **Edit the `.env` file** in the root directory with the following content:

   ```env
   SNYK_API_TOKEN=your-token-here
   BASE_EXPORT_DIR= /Users/[your-name]/Issues_Export_Script/snyk_exports
   LOG_FILE=./logs/snyk_filter_all.log
   PROJECT_ORIGIN=github-cloud-app
   ```

   - Replace `your-token-here` with your actual Snyk API token.
   - `BASE_EXPORT_DIR` should point to the directory containing your Snyk export CSV files.
   - `LOG_FILE` will store the logs generated during script execution.
   - `PROJECT_ORIGIN` should be set to `github-cloud-app`.

3. **Create the necessary directories** if they do not already exist:

   ```bash
   mkdir -p ./logs ./filtered_data
   ```

4. **Add the organization IDs to `config.json`**:

   Edit the file named `config.json` in the root directory (if it doesn’t exist already), and add the organization IDs you want to process:

   ```json
   {
     "org_ids": [
       "org-12345678-aaaa-bbbb-cccc-1234567890ab",
       "org-87654321-dddd-eeee-ffff-0987654321ba"
     ]
   }
   ```

   - Replace the example org IDs with your actual Snyk organization IDs.
   - This file is used by the script to filter or reference data specific to your organizations.

5. **[Optional] Customize the date range in `exporter.py`**:

   The `exporter.py` file is used automatically to fetch and filter data. If you need to change the date range for the issues being exported, edit lines 40–44:
   
   ```src/exporter.py
   {
   "filters": {
     "introduced": {
       "from": "2025-01-30T00:00:00Z",
       "to": "2025-04-01T00:00:00Z"
        }
      }
   }
   ```

## Running the Scripts

### Run `main.py.py` Script

Run this script to automatically fetch vulnerabilities across all specified orgs in config.json and within the configured date range.

```bash
python main.py
```

This will:

- Query Snyk’s REST API for each org
- Apply the introduced date filter
- Save issues into structured folders (e.g., output/org-[org-name]/)
- Log progress and errors to the path defined in .env

### Run `issues_filter.py` Script

The `issues_filter.py` script processes and filters Snyk export CSV files based on the criteria specified in the script. It outputs the filtered data into organized subdirectories.

To run the script, execute the following:

```bash
python issues_filter.py
```

This will:

- Search the `BASE_EXPORT_DIR` for Snyk export files.
- Filter data based on severity (e.g., 'high' or 'critical'), product (e.g., "Snyk Open Source"), issue type (e.g., "vulnerability"), and project origin (e.g., `github-enterprise`).
- Save the filtered results in subdirectories such as `filtered_open_source`, `filtered_code_vulns`, etc.

Logs are saved in `snyk_filter_all.log` for debugging and tracking the script’s progress.

## Output Structure

Running `main.py`
Downloads CSV files from an S3 bucket for each Snyk organization and saves them locally under:

```bash
/Users/your-name/issues_export_script/snyk_exports/org_name
```
These files contain all vulnerabilities and license issues for the organization within the date range configured in `exporter.py`.

**Filtered CSV Output (issues_filter.py)**

Running `issues_filter.py` filters these local CSV exports by severity, issue type, product, and origin. The filtered results are saved in:

```bash
/Users/your-name/issues_export_script/snyk_exports/org_name/filtered_[type]
```
Where [type] includes open_source, code_vulns, and license_issues.

## Logging

- All logs are stored in the `./logs` directory.
- The `snyk_filter_all.log` file contains detailed information on the script's execution and any errors or issues that may arise.

## Contributing

Contributions are welcome! If you find any bugs or would like to suggest improvements, please feel free to open an issue or submit a pull request.
