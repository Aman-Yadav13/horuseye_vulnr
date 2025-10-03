import logging
import os
import json
from flask import Flask, request, jsonify
from app.models import ScanRequest
from tasks import run_vulnerability_scan

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Provides a simple health check endpoint."""
    return jsonify({"status": "healthy"}), 200

@app.route('/scan', methods=['POST'])
def submit_scan():
    """
    Receives a scan request, validates it, and queues it as a background job.
    Returns immediately with a scan ID.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400

        # Validate request data. Pydantic will raise an error if it's malformed.
        scan_request = ScanRequest(**data)
        
        # Send the scan job to the Celery worker.
        # .delay() is the shortcut to send a task to the queue.
        run_vulnerability_scan.delay(scan_request.model_dump())
        
        logger.info(f"Scan job queued for target: {scan_request.target}, ID: {scan_request.scan_id}")
        
        return jsonify({
            "message": "Scan job accepted.",
            "scan_id": scan_request.scan_id
        }), 202 # 202 Accepted
        
    except Exception as e:
        logger.exception("Error processing /scan request")
        return jsonify({"error": "Failed to queue scan job", "details": str(e)}), 500

@app.route('/results/<string:scan_id>', methods=['GET'])
def get_results(scan_id):
    """
    Checks for and returns the results of a completed scan.
    """
    try:
        project_root = "/app"
        result_file_path = os.path.join(project_root, "outputs", scan_id, "final_results.json")

        if os.path.exists(result_file_path):
            with open(result_file_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
            return jsonify(results), 200 # 200 OK
        else:
            return jsonify({
                "status": "pending",
                "message": "Scan is still in progress or does not exist."
            }), 202 # 202 Accepted (still processing)

    except Exception as e:
        logger.exception(f"Error retrieving results for scan_id: {scan_id}")
        return jsonify({"error": "Could not retrieve scan results", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)

