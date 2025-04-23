# main.py

from src.logger import setup_logging
from src.config_loader import load_config_and_token
from src.exporter import run_exports

def main():
    # Initialize logging
    logger = setup_logging()

    try:
        # Load org IDs and API token
        org_ids, token = load_config_and_token(logger)

        # Run export process
        run_exports(org_ids, token, logger)

    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()