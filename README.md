## 📦 Snyk Issues Export Script

This script automates the export of issue data from the [Snyk REST API](https://docs.snyk.io/api/rest) for one or more organizations. It exports issue reports as CSV files and saves them locally for further analysis.

### 🔧 Features

- Supports exporting from multiple Snyk organizations using a config file
- Fetches issue data within a specific time window
- Saves CSV export files to a structured local directory
- Includes logging to both file and console for visibility
- Uses the Snyk REST API (not the legacy API)

---

### 📁 Directory Structure

After running, the output will look like:

```
snyk_exports/
├── org-1-id/
│   ├── snyk_export_org-1-id_exportid_1.csv
│   └── ...
├── org-2-id/
│   └── snyk_export_org-2-id_exportid_1.csv
```

---

### 📋 Prerequisites

- Python 3.7+
- A valid [Snyk API token](https://docs.snyk.io/api-authentication)
- Your organization IDs

---

### 📂 Configuration

1. **Set the Snyk API Token** as an environment variable:
   ```bash
   export SNYK_API_TOKEN=your-token-here
   ```

2. **Create a `config.json` file** in the same directory:
   ```json
   {
     "org_ids": [
       "org-1-id",
       "org-2-id"
     ]
   }
   ```

---

### 🚀 Running the Script

```bash
python snyk_export.py
```

---

### 🧾 Logging

- Logs to `snyk_export.log`
- Also logs to the console (stdout)

You can change the log level by modifying `LOG_LEVEL` in the script:
```python
LOG_LEVEL = logging.DEBUG  # For verbose logs
```

