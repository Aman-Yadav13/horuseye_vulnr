import logging
import os
import json
from celery_app import celery
from app.models import ScanRequest, ScanResponse, ToolOutput
from app.tool_runner import ToolRunner
from typing import Callable 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@celery.task(name='tasks.run_vulnerability_scan')
def run_vulnerability_scan(scan_request_data: dict):
    """
    This is the Celery task wrapper.
    It's kept for potential testing but is NOT used by Argo.
    """
    logger.warning("Executing scan via CELERY (testing only)")
    execute_scan_logic(scan_request_data, lambda tool_name, status: None)


def execute_scan_logic(scan_request_data: dict, update_status_callback: Callable[[str, str], None]):
    """
    This is the core scan logic, separated from the Celery task.
    It can be called directly by any script.
    """
    try:
        scan_request = ScanRequest(**scan_request_data)
        logger.info(f"Worker starting scan for target: {scan_request.target}, ID: {scan_request.scan_id}")

        results = []
        for tool_req in scan_request.tools:
            tool_name = tool_req.name
            try:
                # --- NEW: Report 'running' status ---
                update_status_callback(tool_name, "running")

                builder = ToolRunner.get_command_builder(tool_req.name)
                command = builder(
                    target=scan_request.target,
                    parameters=tool_req.parameters,
                    scan_id=scan_request.scan_id,
                    tool_name=tool_req.name
                )
                tool_result = ToolRunner.execute_command(
                    command,
                    scan_id=scan_request.scan_id,
                    tool_name=tool_req.name
                )
                results.append(tool_result)
                
                # --- NEW: Report 'completed' status ---
                update_status_callback(tool_name, "completed")

            except Exception as e:
                error_msg = f"Worker error running '{tool_req.name}': {e}"
                logger.exception(error_msg)
                
                # --- NEW: Report 'failed' status ---
                update_status_callback(tool_name, "failed")

                results.append(ToolOutput(tool_name=tool_req.name, command=[], return_code=-1, stdout="", stderr=error_msg, output_file_paths=[], success=False))

        all_success = all(res.success for res in results)
        status = "success" if all_success else "partial_failure" if any(res.success for res in results) else "failed"
        message = "Scan completed by worker."

        final_response = ScanResponse(
            scan_id=scan_request.scan_id,
            target=scan_request.target,
            results=results,
            message=message,
            status=status
        )

        # Save the final result to a JSON file
        project_root = "/app"
        output_dir = os.path.join(project_root, "outputs", scan_request.scan_id)
        os.makedirs(output_dir, exist_ok=True)
        result_file_path = os.path.join(output_dir, "final_results.json")

        with open(result_file_path, 'w', encoding='utf-8') as f:
            f.write(final_response.model_dump_json(indent=4))

        logger.info(f"Scan {scan_request.scan_id} completed. Results saved to {result_file_path}")
        return {"status": "complete", "scan_id": scan_request.scan_id}

    except Exception as e:
        logger.exception(f"A critical error occurred in the worker task for scan data: {scan_request_data}")
        # Re-raise the exception
        raise

