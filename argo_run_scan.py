import os
import json
import logging
import sys
import time
import random
from google.cloud import storage
from google.cloud import pubsub_v1  # <-- FIX: Added this import
from app.models import ScanRequest, ToolExecutionRequest, ToolParameter
from tasks import execute_scan_logic # Import the refactored logic

# --- Logger Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ArgoWorker-Vuln")
# --- ---

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
        # 1. Get parameters from Environment Variables
        scan_id = os.environ['SCAN_ID']
        target = os.environ['TARGET']
        gcs_bucket = os.environ['GCS_BUCKET_NAME']
        gcp_project_id = os.environ['GCP_PROJECT_ID']
        pubsub_topic = os.environ['VULN_PUB_SUB_TOPIC']

        logger.info(f"Starting scan for ID: {scan_id} on Target: {target}")

        # 2. Construct GCS path and download payload
        # Path where recon service stored the vuln payload
        blob_path = f"data/{scan_id}/vulnr-payload.json" 
        
        tools_payload_list = download_payload_from_gcs(gcs_bucket, blob_path)
        
        if not tools_payload_list:
            raise Exception("Failed to get vulnerability tools payload from GCS.")

        # 3. Reconstruct ScanRequest data for the logic function
        # Pydantic models expect lists of objects, not dicts
        tool_execution_requests = [
            ToolExecutionRequest(
                name=tool['name'],
                parameters=[ToolParameter(**param) for param in tool['parameters']]
            ) for tool in tools_payload_list
        ]

        scan_request_data = ScanRequest(
            target=target,
            scan_id=scan_id,
            tools=tool_execution_requests
        ).model_dump() # Convert to dict for the logic function

        # 4. Call the core logic
        result = execute_scan_logic(scan_request_data)
        logger.info(f"Scan logic completed. Result: {result}")
        
        if result.get("status") != "complete":
             raise Exception(f"Scan logic failed, result: {result}")
             
        # 5. Publish completion message
        logger.info("Vulnerability scan complete. Publishing to Pub/Sub...")
        publish_to_pubsub(
            project_id=gcp_project_id,
            topic_id=pubsub_topic,
            scan_id=scan_id,
            target=target
        )

        logger.info("--- Argo Worker Complete ---")
        
    except Exception as e:
        logger.error(f"Scan logic failed with a critical error: {e}")
        logger.info("--- Argo Worker Failed ---")
        sys.exit(1) # Exit with error code to fail the Argo pod

if __name__ == "__main__":
    main()

