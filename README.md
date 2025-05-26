# Issues Export Script

This repository contains Python scripts designed to filter and process Snyk export data from CSV files. It allows users to filter vulnerabilities and license issues based on various criteria such as severity, product, issue type, and project origin (e.g., GitHub Enterprise). The filtered results are saved into organized subdirectories.

## Prerequisites

Before running the scripts, make sure you have:

- Python 3.x installed on your machine.
- `pip` for installing Python dependencies.

### Required Python Libraries

To install the required dependencies, run the following command in your terminal:

```bash
pip install -r requirements.txt
```

This will install:

- `pandas`: Used for data processing and manipulation.
- `python-dotenv`: Helps load environment variables from the `.env` file.

## Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/ily-snyk/Issues_Export_Script.git
   cd Issues_Export_Script
   ```

2. **Edit the `.env` file** in the root directory with the following content:

   ```env
   SNYK_API_TOKEN=your-token-here
   BASE_EXPORT_DIR= /Users/[your-name]/Issues_Export_Script/snyk_exports
   LOG_FILE=./logs/snyk_filter_all.log
   PROJECT_ORIGIN=github-enterprise
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

### Running Multiple Scripts Together

If you need to run multiple scripts sequentially, you can create a custom script to execute them. For example:

```python
import subprocess

# Run the issues_filter.py script
print("Running issues_filter.py...")
subprocess.run(["python", "issues_filter.py"])

# Run any additional scripts (if necessary)
print("Running additional_script.py...")
subprocess.run(["python", "additional_script.py"])

print("Both scripts have completed successfully.")
```

Save this script as `run_all_scripts.py` and execute it with:

```bash
python run_all_scripts.py
```

## Logging

- All logs are stored in the `./logs` directory.
- The `snyk_filter_all.log` file contains detailed information on the script's execution and any errors or issues that may arise.

## Contributing

Contributions are welcome! If you find any bugs or would like to suggest improvements, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.
