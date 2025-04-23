# src/config_loader.py
import os
import json
from dotenv import load_dotenv

def load_config_and_token(logger, config_file="config.json"):
    load_dotenv()

    snyk_token = os.getenv("SNYK_API_TOKEN")
    if not snyk_token:
        logger.error("The SNYK_API_TOKEN environment variable is not set.")
        raise EnvironmentError("Missing SNYK_API_TOKEN.")

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
            org_ids = config.get("org_ids", [])
    except FileNotFoundError:
        logger.error(f"Error: {config_file} not found.")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Error: Invalid JSON in {config_file}: {e}")
        raise

    if not org_ids:
        logger.warning("No organization IDs found in the config file.")

    return org_ids, snyk_token