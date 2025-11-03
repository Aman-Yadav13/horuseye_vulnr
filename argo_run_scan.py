import os
import json
import logging
import sys
import time
import random
import requests 
import datetime 
from functools import partial 

from google.cloud import storage
from google.cloud import pubsub_v1  
from app.models import ScanRequest, ToolExecutionRequest, ToolParameter
from tasks import execute_scan_logic 

# --- Logger Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ArgoWorker-Vuln")
# --- ---

FASTAPI_INTERNAL_URL = "http://fastapi-gateway-svc.default.svc.cluster.local:80/api/v1/internal"

def update_scan_status(scan_id: str, status: str):
    """Calls the internal FastAPI endpoint to update the overall Scan status."""
    try:
        payload = {"scan_id": scan_id, "status": status}
        response = requests.post(f"{FASTAPI_INTERNAL_URL}/scan/status", json=payload, timeout=5)
        response.raise_for_status() # Raise an exception for bad status codes
        logger.info(f"Successfully updated Scan {scan_id} status to {status}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to update Scan status to {status} for {scan_id}: {e}")

def update_tool_status(scan_id: str, tool_name: str, status: str):
    """Calls the internal FastAPI endpoint to update a specific ToolExecution status."""
    try:
        payload = {
            "scan_id": scan_id,
            "tool_name": tool_name,
            "status": status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        response = requests.post(f"{FASTAPI_INTERNAL_URL}/tool/status", json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Successfully updated Tool {tool_name} for Scan {scan_id} to {status}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to update Tool {tool_name} status to {status} for {scan_id}: {e}")

def download_payload_from_gcs(bucket_name: str, blob_path: str) -> dict | None:
    """Downloads the specific vulnerability payload from GCS."""
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        # --- FIX: Use the correct path structure ---
        # The recon service saved it to: data/{scan_id}/vulnr-payload.json
        # blob_path = f"{scan_id}/vulnr-payload.json" (This was the old path)
        # We will use the full path passed in the env var, which is now correct.
        # Example: data/test-scan-002/vulnr-payload.json
        
        logger.info(f"Downloading payload from gs://{bucket_name}/{blob_path}")
        blob = bucket.blob(blob_path)
        
        payload_content = blob.download_as_text()
        
        payload_dict = json.loads(payload_content)
        logger.info("Successfully downloaded and parsed payload.")
        return payload_dict
        
    except Exception as e:
        logger.error(f"Failed to download or parse payload from GCS: {e}")
        return None

def publish_to_pubsub(project_id: str, topic_id: str, scan_id: str, target: str, max_retries: int = 5):
    """
    Publishes a message to a Pub/Sub topic with production-grade retries.
    """
    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_id)
    
    message_data = {
        "scan_id": scan_id,
        "target": target,
        "status": "vuln_complete"
    }
    data = json.dumps(message_data).encode("utf-8")

    base_delay_seconds = 1
    jitter_max = 0.5

    for attempt in range(max_retries):
        try:
            future = publisher.publish(topic_path, data)
            message_id = future.result(timeout=30)
            logger.info(f"Successfully published message {message_id} to {topic_path} on attempt {attempt + 1}")
            return
            
        except Exception as e:
            logger.warning(f"Failed to publish Pub/Sub message (Attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                logger.error(f"CRITICAL: Failed to publish Pub/Sub message after {max_retries} attempts. Giving up.")
                return # Do not crash the pod, just log the error

            delay = (base_delay_seconds * 2**attempt) + (random.random() * jitter_max)
            logger.info(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)

def main():
    logger.info("--- Argo Worker Entrypoint (Vulnerability) ---")
    
    try:
        scan_id = os.environ['SCAN_ID']
        target = os.environ['TARGET']
        
        gcp_project_id = os.environ['GCP_PROJECT_ID']
        pubsub_topic_id = os.environ['VULN_PUB_SUB_TOPIC'] 
        gcs_bucket_name = os.environ['GCS_BUCKET_NAME']

    except KeyError as e:
        logger.error(f"Missing environment variable: {e}")
        sys.exit(1)

    logger.info(f"Starting scan for ID: {scan_id} on Target: {target}")

    try:
        blob_path = f"data/{scan_id}/vulnr-payload.json" 

        tools_payload_list = download_payload_from_gcs(gcs_bucket_name, blob_path)
        
        scan_request_data = {
            "scan_id": scan_id,
            "target": target,
            "tools": tools_payload_list # The list of tools is the downloaded dict
        }
        logger.info(f"Successfully parsed {len(tools_payload_list)} vuln tools from GCS payload.")
        
    except Exception as e:
        logger.error(f"Failed to get payload from GCS: {e}")
        sys.exit(1)

    try:
        # --- NEW: Update Scan status to 'vuln_running' ---
        update_scan_status(scan_id, "vuln_running")
        
        # --- NEW: Create a callback function ---
        tool_status_callback = partial(update_tool_status, scan_id)

        logger.info("Handing off to vulnerability scan logic...")
        # --- NEW: Pass the callback to the logic function ---
        result = execute_scan_logic(scan_request_data, tool_status_callback)
        logger.info(f"Vulnerability scan logic completed. Result: {result}")

        # --- NEW: Update Scan status to 'vuln_complete' ---
        update_scan_status(scan_id, "vuln_complete")

        logger.info("Vulnerability scan complete. Publishing to Pub/Sub...")
        publish_to_pubsub(gcp_project_id, pubsub_topic_id, scan_id, target)
        
        logger.info("--- Argo Worker Complete ---")
        sys.exit(0)

    except Exception as e:
        logger.exception(f"Scan logic failed with a critical error: {e}")
        # --- NEW: Update Scan status to 'failed' ---
        update_scan_status(scan_id, "failed")
        logger.info("--- Argo Worker Failed ---")
        sys.exit(1)

if __name__ == "__main__":
    main()

