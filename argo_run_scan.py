import os
import json
import logging
import sys
from google.cloud import storage
from tasks import execute_scan_logic

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ArgoWorker-Vuln")

def download_payload_from_gcs(bucket_name, scan_id) -> dict:
    """
    Downloads the vulnerability tool payload from GCS.
    
    The payload is expected to be at:
    gs://[bucket_name]/[scan_id]/vulnr-payload.json
    """
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        blob_path = f"data/{scan_id}/vulnr-payload.json" 
        blob = bucket.blob(blob_path)
        
        logger.info(f"Downloading payload from gs://{bucket_name}/{blob_path}")
        
        payload_content = blob.download_as_text()
        
        if not payload_content:
            logger.error("Downloaded payload is empty.")
            sys.exit(1)
            
        tools_list = json.loads(payload_content)
        logger.info(f"Successfully downloaded and parsed {len(tools_list)} tools from GCS.")
        return tools_list

    except Exception as e:
        logger.exception(f"Failed to download or parse payload from GCS: {e}")
        sys.exit(1)


def main():
    logger.info("--- Argo Worker Entrypoint (Vulnerability) ---")

    try:
        scan_id = os.environ['SCAN_ID']
        target = os.environ['TARGET']
        bucket_name = os.environ['GCS_BUCKET_NAME']
    except KeyError as e:
        logger.error(f"Missing environment variable: {e}")
        sys.exit(1)

    logger.info(f"Starting scan for ID: {scan_id} on Target: {target}")

    tools_list = download_payload_from_gcs(bucket_name, scan_id)

    scan_request_data = {
        "scan_id": scan_id,
        "target": target,
        "tools": tools_list
    }

    try:
        logger.info("Handing off to scan logic...")
        result = execute_scan_logic(scan_request_data)
        logger.info(f"Scan logic completed. Result: {result}")
        
        # TODO: In the future, this service will publish its *own*
        # message (e.g., 'vuln_scan_complete') to trigger the
        # reporting service. We can add that later.
        
        logger.info("--- Argo Worker Complete ---")
        sys.exit(0) 

    except Exception as e:
        logger.exception(f"Scan logic failed with a critical error: {e}")
        logger.info("--- Argo Worker Failed ---")
        sys.exit(1) # Fail the workflow

if __name__ == "__main__":
    main()
