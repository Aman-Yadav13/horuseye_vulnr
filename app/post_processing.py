import os
import logging
from typing import Dict, Callable, List
from app.gcs_utils import upload_file_to_gcs, delete_local_directory

logger = logging.getLogger(__name__)

_post_processor_registry: Dict[str, Callable] = {}

def register_post_processor(tool_name: str) -> Callable:
    """A decorator to register a post-processing function for a tool."""
    def decorator(func: Callable) -> Callable:
        _post_processor_registry[tool_name.lower()] = func
        logger.info(f"Registered post-processor for tool: {tool_name}")
        return func
    return decorator

def get_post_processor(tool_name: str) -> Callable:
    """Retrieves the post-processing function for a tool, or a default."""
    processor = _post_processor_registry.get(tool_name.lower(), default_post_processor)
    logger.info(f"Using post-processor '{processor.__name__}' for tool '{tool_name}'")
    return processor

def default_post_processor(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Default handler: Uploads all generated files for review and cleans up.
    """
    logger.info(f"Running default post-processor for {tool_name}")
    all_uploads_succeeded = True
    for file_path in output_files:
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            # Upload all files to the 'review' folder by default
            gcs_path = f"data/{scan_id}/vulnr/{tool_name}/review/{filename}"
            if not upload_file_to_gcs(file_path, gcs_path):
                all_uploads_succeeded = False
    
    if all_uploads_succeeded:
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to GCS upload failures.")

@register_post_processor("nuclei")
def post_process_nuclei(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Nuclei.
    - Consolidates stdout and stderr for an LLM.
    - Uploads raw outputs for review.
    - Cleans up local files.
    """
    logger.info("Running custom post-processor for Nuclei")
    
    stdout_file = os.path.join(output_dir, "output.stdout")
    stderr_file = os.path.join(output_dir, "output.stderr")
    json_file = os.path.join(output_dir, "nuclei_results.json")
    
    stdout_content = ""
    stderr_content_processed = ""
    
    if os.path.exists(stdout_file):
        with open(stdout_file, 'r', encoding='utf-8') as f:
            stdout_content = f.read()
            
    if os.path.exists(stderr_file):
        with open(stderr_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Keep only the first 12 lines of stderr as requested
            stderr_content_processed = "".join(lines[12:])

    llm_input_content = f'stdout: """{stdout_content}"""\n\nstderr: """{stderr_content_processed}"""'
    
    compiled_llm_file = os.path.join(output_dir, "compiled_llm_input.txt")
    with open(compiled_llm_file, 'w', encoding='utf-8') as f:
        f.write(llm_input_content)

    uploads = {
        "llm": upload_file_to_gcs(
            compiled_llm_file, f"data/{scan_id}/vulnr/{tool_name}/llm/compiled_llm_input.txt"
        ),
        "stdout_review": upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout"
        ),
        "stderr_review": upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stderr"
        )
    }

    if all(uploads.values()):
        logger.info("All Nuclei artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        failed = [k for k, v in uploads.items() if not v]
        logger.error(f"Skipping cleanup for {output_dir} due to failed GCS uploads for: {failed}")
        
@register_post_processor("nikto")
def post_process_nikto(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Nikto.
    - Uploads the text output (stdout) for the LLM.
    - Uploads both the raw text (stdout) and JSON outputs for review.
    - Ignores stderr.
    - Cleans up local files.
    """
    logger.info("Running custom post-processor for Nikto")

    stdout_file = os.path.join(output_dir, "output.stdout")
    json_file = os.path.join(output_dir, "nikto_results.json")
    
    uploads_succeeded = []

    if os.path.exists(stdout_file):
        llm_upload_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/llm/nikto_llm_input.txt"
        )
        uploads_succeeded.append(llm_upload_success)
    else:
        logger.warning(f"Nikto stdout file not found at {stdout_file}, skipping LLM upload.")
        # If the main file is missing, we consider it a failure for cleanup purposes
        uploads_succeeded.append(False)

    if os.path.exists(stdout_file):
        review_stdout_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout"
        )
        uploads_succeeded.append(review_stdout_success)
    
    if os.path.exists(json_file):
        review_json_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/review/nikto_results.json"
        )
        uploads_succeeded.append(review_json_success)
    else:
        logger.warning(f"Nikto JSON file not found at {json_file}, skipping review upload.")

    if all(uploads_succeeded):
        logger.info("All Nikto artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to one or more failed GCS uploads.")

@register_post_processor("sqlmap")
def post_process_sqlmap(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for sqlmap.
    - Finds the dynamic output directory created by sqlmap.
    - Uploads the 'log' file for the LLM.
    - Uploads stdout and the 'log' file for review.
    - Cleans up.
    """
    logger.info("Running custom post-processor for sqlmap")
    uploads_succeeded = []
    
    stdout_file = os.path.join(output_dir, "output.stdout")
    
    sqlmap_result_dir = None
    for item in os.listdir(output_dir):
        path = os.path.join(output_dir, item)
        if os.path.isdir(path):
            sqlmap_result_dir = path
            break # Assume the first directory found is the correct one

    if not sqlmap_result_dir:
        logger.error(f"Could not find sqlmap output subdirectory in {output_dir}")
        if os.path.exists(stdout_file):
            upload_file_to_gcs(stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout_FAILURE")
        delete_local_directory(output_dir) # Cleanup to avoid orphaned files
        return

    log_file = os.path.join(sqlmap_result_dir, "log")

    if os.path.exists(log_file):
        llm_success = upload_file_to_gcs(
            log_file, f"data/{scan_id}/vulnr/{tool_name}/llm/sqlmap_log.txt"
        )
        uploads_succeeded.append(llm_success)
    else:
        logger.warning(f"sqlmap log file not found at {log_file}")
        uploads_succeeded.append(False)

    if os.path.exists(stdout_file):
        review_stdout_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout"
        )
        uploads_succeeded.append(review_stdout_success)
        
    if os.path.exists(log_file):
        review_log_success = upload_file_to_gcs(
            log_file, f"data/{scan_id}/vulnr/{tool_name}/review/log.txt"
        )
        uploads_succeeded.append(review_log_success)

    if all(uploads_succeeded):
        logger.info("All sqlmap artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to sqlmap upload failures.")

@register_post_processor("trivy")
def post_process_trivy(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Trivy.
    - Uploads the JSON result file for review.
    - Does not create an LLM file.
    - Cleans up all local files.
    """
    logger.info("Running custom post-processor for Trivy")

    json_file = os.path.join(output_dir, "trivy_results.json")
    
    upload_succeeded = False

    if os.path.exists(json_file):
        upload_succeeded = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/review/trivy_results.json"
        )
    else:
        logger.error(f"Trivy JSON output not found at {json_file}")

    if upload_succeeded:
        logger.info("Trivy artifact uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Trivy upload failure.")
        
@register_post_processor("lynis")
def post_process_lynis(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Lynis.
    - Saves only the standard output for review.
    - Does not create an LLM file.
    - Deletes all local log and report files.
    """
    logger.info("Running custom post-processor for Lynis")

    stdout_file = os.path.join(output_dir, "output.stdout")
    
    upload_succeeded = False

    if os.path.exists(stdout_file):
        upload_succeeded = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/lynis_audit_output.txt"
        )
    else:
        logger.error(f"Lynis stdout output not found at {stdout_file}")

    if upload_succeeded:
        logger.info("Lynis artifact uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Lynis upload failure.")

@register_post_processor("wpscan")
def post_process_wpscan(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for WPScan.
    - Uploads the JSON result file to both LLM and review directories.
    - Deletes all other local files.
    """
    logger.info("Running custom post-processor for WPScan")

    json_file = os.path.join(output_dir, "wpscan_results.json")
    
    uploads_succeeded = []

    if os.path.exists(json_file):
        llm_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/llm/wpscan_results.json"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/review/wpscan_results.json"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"WPScan JSON output not found at {json_file}")
        uploads_succeeded.append(False) # Ensure cleanup is skipped

    if all(uploads_succeeded):
        logger.info("WPScan artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to WPScan upload failures.")

@register_post_processor("semgrep")
def post_process_semgrep(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Semgrep.
    - Uploads stderr (which often contains the summary) to LLM and review.
    - Deletes all local files, including the cloned source code.
    """
    logger.info("Running custom post-processor for Semgrep")

    stderr_file = os.path.join(output_dir, "output.stderr")
    uploads_succeeded = []

    if os.path.exists(stderr_file):
        llm_success = upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/vulnr/{tool_name}/llm/semgrep_scan_output.txt"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stderr"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Semgrep stderr output not found at {stderr_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Semgrep artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Semgrep upload failures.")
        
        
@register_post_processor("trufflehog")
def post_process_trufflehog(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Trufflehog.
    - Uploads stdout (which contains found secrets) to LLM and review.
    - Deletes all local files.
    """
    logger.info("Running custom post-processor for Trufflehog")

    stdout_file = os.path.join(output_dir, "output.stdout")
    uploads_succeeded = []

    if os.path.exists(stdout_file):
        # Upload for LLM
        llm_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/llm/trufflehog_scan_output.txt"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Trufflehog stdout output not found at {stdout_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Trufflehog artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Trufflehog upload failures.")

@register_post_processor("gitleaks")
def post_process_gitleaks(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Gitleaks.
    - Uploads the JSON result file to both LLM and review directories.
    - Deletes all other local files.
    """
    logger.info("Running custom post-processor for Gitleaks")

    json_file = os.path.join(output_dir, "gitleaks_results.json")
    uploads_succeeded = []

    if os.path.exists(json_file):
        llm_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/llm/gitleaks_results.json"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/vulnr/{tool_name}/review/gitleaks_results.json"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Gitleaks JSON output not found at {json_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Gitleaks artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Gitleaks upload failures.")
        
# In post_processing.py

# ... (imports and other functions remain the same)

@register_post_processor("yara")
def post_process_yara(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Yara.
    - Uploads stderr (which contains rule matches) to LLM and review.
    - Deletes all local files.
    """
    logger.info("Running custom post-processor for Yara")

    stderr_file = os.path.join(output_dir, "output.stderr")
    uploads_succeeded = []

    if os.path.exists(stderr_file):
        # Upload for LLM with a more descriptive name
        llm_success = upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/vulnr/{tool_name}/llm/yara_scan_output.txt"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stderr"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Yara stderr output not found at {stderr_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Yara artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Yara upload failures.")
        
@register_post_processor("httpx")
def post_process_httpx(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for httpx.
    - Creates a summary (top 20 lines) of stdout for the LLM.
    - Uploads the full stdout file for review.
    - Deletes all local files.
    """
    logger.info("Running custom post-processor for httpx")

    stdout_file = os.path.join(output_dir, "output.stdout")
    uploads_succeeded = []
    
    if not os.path.exists(stdout_file):
        logger.error(f"httpx stdout output not found at {stdout_file}")
        uploads_succeeded.append(False)
    else:
        summary_file_path = os.path.join(output_dir, "httpx_summary.txt")
        try:
            with open(stdout_file, 'r', encoding='utf-8') as f_in:
                # Read the first 20 lines
                summary_lines = [next(f_in) for _ in range(20)]
            
            with open(summary_file_path, 'w', encoding='utf-8') as f_out:
                f_out.writelines(summary_lines)
            
            llm_success = upload_file_to_gcs(
                summary_file_path, f"data/{scan_id}/vulnr/{tool_name}/llm/httpx_summary.txt"
            )
            uploads_succeeded.append(llm_success)

        except StopIteration: # Handles files with less than 20 lines
            logger.info("File has less than 20 lines, using full content for summary.")
            llm_success = upload_file_to_gcs(
                stdout_file, f"data/{scan_id}/vulnr/{tool_name}/llm/httpx_summary.txt"
            )
            uploads_succeeded.append(llm_success)
        except Exception as e:
            logger.error(f"Failed to create httpx summary file: {e}")
            uploads_succeeded.append(False)
        
        review_success = upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/vulnr/{tool_name}/review/output.stdout"
        )
        uploads_succeeded.append(review_success)

    if all(uploads_succeeded):
        logger.info("httpx artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to httpx upload failures.")