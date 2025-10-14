import os
import logging
import shutil
from google.cloud import storage

logger = logging.getLogger(__name__)

def get_gcs_client():
    """Initializes and returns a GCS storage client."""
    try:
        storage_client = storage.Client()
        return storage_client
    except Exception as e:
        logger.error(f"Failed to initialize GCS client: {e}")
        return None

def upload_file_to_gcs(local_file_path: str, destination_blob_name: str):
    """Uploads a single file to the specified GCS bucket and blob name."""
    client = get_gcs_client()
    if not client:
        return False

    bucket_name = os.getenv("GCS_BUCKET_NAME")
    if not bucket_name:
        logger.error("GCS_BUCKET_NAME environment variable not set.")
        return False

    try:
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_filename(local_file_path)
        logger.info(f"Successfully uploaded {local_file_path} to gs://{bucket_name}/{destination_blob_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload {local_file_path} to GCS: {e}")
        return False

def delete_local_directory(directory_path: str):
    """Safely deletes a local directory and all its contents."""
    if not os.path.isdir(directory_path):
        logger.warning(f"Attempted to delete non-existent directory: {directory_path}")
        return
    try:
        shutil.rmtree(directory_path)
        logger.info(f"Successfully deleted local directory: {directory_path}")
    except Exception as e:
        logger.error(f"Failed to delete local directory {directory_path}: {e}")