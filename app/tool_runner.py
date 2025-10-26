import subprocess
import logging
import shlex
from typing import List, Callable, Dict, Tuple, Optional
from app.models import ToolOutput, ToolParameter
import os
from app.post_processing import default_post_processor, get_post_processor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def _clone_repo(repo_url: str, scan_id: str, tool_name: str) -> Tuple[Optional[str], Optional[List[str]]]:
    """Helper function to clone a git repository."""
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    source_dir = os.path.join(output_dir, "source")
    if os.path.exists(source_dir):
        import shutil
        shutil.rmtree(source_dir)
    os.makedirs(source_dir, exist_ok=True)

    clone_cmd = ["git", "clone", "--depth", "1", repo_url, source_dir]
    logger.info(f"Cloning repository: {' '.join(clone_cmd)}")
    clone_result = subprocess.run(clone_cmd, capture_output=True, text=True, check=False)

    if clone_result.returncode != 0:
        error_msg = f"Failed to clone repository: {clone_result.stderr.strip()}"
        logger.error(error_msg)
        return None, ["sh", "-c", f"echo '{error_msg}' >&2 && exit 1"]

    return source_dir, None

class ToolRunner:
    """
    Handles the registration and execution of command-line tools.
    This logic is called by the background Celery worker.
    """
    _tool_registry: Dict[str, Callable] = {}

    @classmethod
    def register_tool(cls, tool_name: str) -> Callable:
        """A decorator to register a command-building function for a tool."""
        def decorator(func: Callable) -> Callable:
            cls._tool_registry[tool_name.lower()] = func
            logger.info(f"Registered tool: {tool_name}")
            return func
        return decorator

    @classmethod
    def get_command_builder(cls, tool_name: str) -> Callable:
        """Retrieves the command-building function for a given tool."""
        builder = cls._tool_registry.get(tool_name.lower())
        if not builder:
            raise ValueError(f"Unsupported tool: {tool_name}")
        return builder

    @staticmethod
    def execute_command(command: List[str], scan_id: str, tool_name: str, timeout: int = 3600) -> ToolOutput:
        """
        Executes a shell command and captures its output, saving results to structured directories.
        """
        project_root = "/app" # Using container path
        output_dir = os.path.join(project_root, "outputs", scan_id, tool_name)
        os.makedirs(output_dir, exist_ok=True)

        stdout_file = os.path.join(output_dir, "output.stdout")
        stderr_file = os.path.join(output_dir, "output.stderr")

        try:
            logger.info(f"Executing command: {shlex.join(command)}")
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, check=False
            )

            with open(stdout_file, 'w', encoding='utf-8') as f_out:
                f_out.write(result.stdout)
            with open(stderr_file, 'w', encoding='utf-8') as f_err:
                f_err.write(result.stderr)

            output_files = [stdout_file, stderr_file]
            for filename in os.listdir(output_dir):
                full_path = os.path.join(output_dir, filename)
                if os.path.isfile(full_path) and full_path not in output_files:
                    output_files.append(full_path)
            
            success = result.returncode == 0
            
            if success:
                logger.info(f"Command for tool '{tool_name}' succeeded. Starting post-processing.")
                post_processor = get_post_processor(tool_name)
                post_processor(scan_id, tool_name, output_dir, output_files)
            else:
                logger.warning(f"Command for tool '{tool_name}' failed. Uploading raw logs for review.")
                default_post_processor(scan_id, tool_name, output_dir, output_files)


            return ToolOutput(
                tool_name=tool_name,
                command=command,
                return_code=result.returncode,
                stdout=result.stdout[-2000:],
                stderr=result.stderr[-2000:],
                output_file_paths=output_files,
                success=success
            )
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds."
            logger.error(error_msg)
            with open(stderr_file, 'w', encoding='utf-8') as f:
                f.write(error_msg)
            
            default_post_processor(scan_id, tool_name, output_dir, [stderr_file])

            return ToolOutput(
                tool_name=tool_name, command=command, return_code=-1, stdout="",
                stderr=error_msg, output_file_paths=[stderr_file], success=False
            )
        except Exception as e:
            error_msg = f"An unexpected error occurred: {str(e)}"
            logger.exception(error_msg)
            return ToolOutput(
                tool_name=tool_name, command=command, return_code=-1, stdout="",
                stderr=error_msg, output_file_paths=[], success=False
            )

@ToolRunner.register_tool("nuclei")
def build_nuclei_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Nuclei. Uses user-provided templates if specified,
    otherwise defaults to the full template repository.
    """
    cmd = ["nuclei", "-u", target]

    # Backend-managed configurations
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    json_output_file = os.path.join(output_dir, "nuclei_results.json")

    # Add mandatory backend flags for output and formatting
    cmd.extend([
        "-no-color",
        "-stats",
        "-jsonl",
        "-o", json_output_file
    ])

    user_template_paths = []
    other_params = []

    # Separate template flags from other parameters
    for param in parameters:
        if param.flag == "-t":
            # Can handle a single path (str) or multiple paths (list)
            if isinstance(param.value, list):
                user_template_paths.extend(param.value)
            elif param.value:
                user_template_paths.append(param.value)
        else:
            other_params.append(param)

    # If user provided templates, use them. Otherwise, default to the full repo.
    if user_template_paths:
        for path in user_template_paths:
            cmd.extend(["-t", str(path)])
    else:
        cmd.extend(["-t", "/root/nuclei-templates"])

    # Process the rest of the parameters
    for param in other_params:
        flag = param.flag
        if not flag:
            continue

        if param.requiresValue and param.value is not None:
            if isinstance(param.value, list):
                cmd.extend([flag, ",".join(map(str, param.value))])
            else:
                cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            if param.value:
                cmd.append(flag)

    logger.info(f"Built nuclei command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("nikto")
def build_nikto_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Nikto.
    """
    # Path to the nikto perl script inside the container
    cmd = ["perl", "/opt/nikto/program/nikto.pl", "-h", target]

    # Backend-managed configurations
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    json_output_file = os.path.join(output_dir, "nikto_results.json")

    # Add mandatory backend flags for JSON output
    cmd.extend(["-Format", "json", "-o", json_output_file])

    # Process user-provided parameters
    for param in parameters:
        flag = param.flag
        if not flag:
            continue

        # Skip backend-managed flags if they are somehow passed from the frontend
        if flag in ["-h", "-o", "-Format"]:
            continue

        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            # For flags like -ssl, append if its value is true
            if param.value:
                cmd.append(flag)

    logger.info(f"Built nikto command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("sqlmap")
def build_sqlmap_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for sqlmap.
    """
    output_dir = f"/app/outputs/{scan_id}/{tool_name}/"
    os.makedirs(output_dir, exist_ok=True)

    # Base command with mandatory non-interactive flag and output directory
    cmd = ["sqlmap", "-u", target, "--batch", "--output-dir", output_dir]

    # Process user-provided parameters
    for param in parameters:
        flag = param.flag
        if not flag:
            continue

        # Skip backend-managed flags
        if flag in ["-u", "--output-dir", "--batch"]:
            continue

        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            # For flags like --dbs, --dump, --random-agent, append if true
            if param.value:
                cmd.append(flag)

    logger.info(f"Built sqlmap command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("trivy")
def build_trivy_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Trivy to scan a container image.
    The 'target' from the main request is ignored; the image name comes from parameters.
    """
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    json_output_file = os.path.join(output_dir, "trivy_results.json")

    # Find the image name from parameters
    image_name = None
    other_params = []
    for p in parameters:
        if p.flag == 'imageName':
            image_name = p.value
        else:
            other_params.append(p)

    if not image_name:
        raise ValueError("Trivy scan requires 'imageName' parameter.")

    # Base command for an image scan with JSON output
    cmd = ["trivy", "image", "--format", "json", "-o", json_output_file, image_name]

    # Process other user-provided parameters
    for param in other_params:
        flag = param.flag
        if not flag:
            continue

        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            if param.value:
                cmd.append(flag)
    
    logger.info(f"Built trivy command: {' '.join(cmd)}")
    return cmd


@ToolRunner.register_tool("lynis")
def build_lynis_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Lynis to audit the local system (the container).
    The 'target' parameter from the main request is ignored for this tool as it audits the local container.
    """
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "lynis.log")
    report_file = os.path.join(output_dir, "lynis-report.dat")


    # Base command for a non-interactive system audit
    cmd = ["lynis", "audit", "system", "--cronjob", "--logfile", log_file, "--report-file", report_file]

    # Process user-provided parameters
    for param in parameters:
        flag = param.flag
        if not flag:
            continue

        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            # For flags like --quick
            if param.value:
                cmd.append(flag)

    logger.info(f"Built lynis command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("wpscan")
def build_wpscan_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for WPScan.
    """
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)
    json_output_file = os.path.join(output_dir, "wpscan_results.json")

    # Ensure the target has a protocol prefix for WPScan
    checked_target = target
    if not target.lower().startswith(('http://', 'https://')):
        checked_target = 'http://' + target

    # Base command with mandatory flags for automation
    cmd = ["wpscan", "--url", checked_target, "--format", "json", "--output", json_output_file, "--no-update"]

    # Process user-provided parameters
    for param in parameters:
        flag = param.flag
        if not flag:
            continue
        
        # WPScan uses --random-user-agent, not --random-agent
        if flag == '--random-agent':
            flag = '--random-user-agent'

        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue:
            if param.value:
                cmd.append(flag)

    logger.info(f"Built wpscan command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("semgrep")
def build_semgrep_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Semgrep. Clones a git repository specified in a 'gitURL' parameter.
    """
    git_url_param = next((p for p in parameters if p.flag == 'gitURL'), None)

    if not git_url_param or not isinstance(git_url_param.value, str):
        error_msg = "Semgrep scan requires a 'gitURL' parameter with a valid git repository URL."
        logger.error(error_msg)
        return ["sh", "-c", f"echo '{error_msg}' >&2 && exit 1"]
    
    repo_url = git_url_param.value
    
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    source_code_dir = os.path.join(output_dir, "source")
    json_report_file = os.path.join(output_dir, "semgrep_results.json")
    
    os.makedirs(source_code_dir, exist_ok=True)

    try:
        logger.info(f"Cloning repository {repo_url} into {source_code_dir} for Semgrep scan...")
        clone_cmd = ["git", "clone", "--depth", "1", repo_url, source_code_dir]
        subprocess.run(clone_cmd, check=True, capture_output=True, text=True)
        logger.info("Repository cloned successfully.")
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to clone repository: {e.stderr.strip()}"
        logger.error(error_msg)
        return ["sh", "-c", f"echo '{error_msg}' >&2 && exit 1"]
    except Exception as e:
        error_msg = f"An unexpected error occurred during git clone: {e}"
        logger.error(error_msg)
        return ["sh", "-c", f"echo '{error_msg}' >&2 && exit 1"]

    cmd = ["semgrep", "scan", "--json", "-o", json_report_file, source_code_dir]
    
    config_provided = any(p.flag == '--config' for p in parameters)
    if not config_provided:
        cmd.extend(["--config", "auto"])

    for param in parameters:
        if param.flag == 'gitURL':
            continue
        
        flag = param.flag
        if not flag:
            continue
        
        if param.requiresValue and param.value is not None:
            cmd.extend([flag, str(param.value)])
        elif not param.requiresValue and param.value:
            cmd.append(flag)

    logger.info(f"Built Semgrep command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("trufflehog")
def build_trufflehog_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    repo_url_param = next((p for p in parameters if p.flag == 'repoURL'), None)
    if not repo_url_param or not isinstance(repo_url_param.value, str):
        error_msg = "Trufflehog scan requires a 'repoURL' parameter with a valid Git repository URL."
        logger.error(error_msg)
        return ["sh", "-c", f"echo '{error_msg}' >&2 && exit 1"]
    
    source_dir, error_cmd = _clone_repo(repo_url_param.value, scan_id, tool_name)
    if error_cmd:
        return error_cmd

    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    json_report_file = os.path.join(output_dir, "trufflehog_results.json")
    
    cmd = ["trufflehog", "filesystem", source_dir, "--json"]
    
    for param in parameters:
        # Ignore repoURL and deprecated flags
        if param.flag in ['repoURL', '--regex', '--entropy']:
            continue
        if not param.requiresValue and param.value:
            cmd.append(param.flag)
            
    logger.info(f"Built Trufflehog command: {' '.join(cmd)}")
    return cmd


@ToolRunner.register_tool("gitleaks")
def build_gitleaks_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    """
    Builds the command for Gitleaks. This version handles repository cloning
    and saves the output to a dedicated JSON file.
    """
    repo_url_param = next((p for p in parameters if p.flag == 'repoURL'), None)
    if not repo_url_param or not isinstance(repo_url_param.value, str):
        return ["sh", "-c", "echo 'Gitleaks scan requires a repoURL parameter.' >&2 && exit 1"]

    clone_dir, clone_error = _clone_repo(repo_url_param.value, scan_id, tool_name)
    if clone_error is not None:
        return clone_error

    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    json_report_file = os.path.join(output_dir, "gitleaks_results.json")
    
    # Gitleaks has a dedicated flag for report generation, which is cleaner.
    cmd = ["gitleaks", "detect", "--source", clone_dir, "-r", json_report_file, "-f", "json"]

    for param in parameters:
        if param.flag == 'repoURL': continue
        if param.requiresValue and param.value is not None:
            cmd.extend([param.flag, str(param.value)])
        elif not param.requiresValue and param.value:
            cmd.append(param.flag)

    logger.info(f"Built Gitleaks command: {shlex.join(cmd)}")
    return cmd

@ToolRunner.register_tool("yara")
def build_yara_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    repo_url_param = next((p for p in parameters if p.flag == 'repoURL'), None)
    if not repo_url_param or not isinstance(repo_url_param.value, str):
        return ["sh", "-c", "echo 'Yara scan requires a repoURL parameter' >&2 && exit 1"]
    source_dir, error_cmd = _clone_repo(repo_url_param.value, scan_id, tool_name)
    if error_cmd: return error_cmd
    # Point to the main index file for the cloned yara rules
    rules_file = "/opt/yara-rules/index.yar"
    cmd = ["yara", "-r", rules_file, source_dir]
    for param in parameters:
        if param.flag == 'repoURL': continue
        if param.requiresValue and param.value is not None:
            cmd.extend([param.flag, str(param.value)])
        elif not param.requiresValue and param.value:
            cmd.append(param.flag)
    logger.info(f"Built Yara command: {' '.join(cmd)}")
    return cmd

@ToolRunner.register_tool("httpx")
def build_httpx_command(target: str, parameters: List[ToolParameter], scan_id: str, tool_name: str) -> List[str]:
    output_dir = f"/app/outputs/{scan_id}/{tool_name}"
    os.makedirs(output_dir, exist_ok=True)

    base_cmd = ["httpx"]

    for param in parameters:
        flag = param.flag
        if not flag:
            continue
        if param.requiresValue and param.value is not None:
            base_cmd.extend([flag, str(param.value)])
        elif not param.requiresValue and param.value:
            base_cmd.append(flag)
            
    normalized_target = target if target.startswith(("http://", "https://")) else f"http://{target}"

    base_cmd.append(normalized_target)


    shell_command = f"echo {shlex.quote(target)} | {' '.join(base_cmd)}"
    logger.info(f"Built HTTPX command: {shell_command}")

    return ["sh", "-c", shell_command]
