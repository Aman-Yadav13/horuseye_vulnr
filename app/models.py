from pydantic import BaseModel, Field, validator, ConfigDict
from typing import List, Optional, Dict, Any

class ToolParameter(BaseModel):
    """
    Defines a single parameter for a command-line tool.
    The 'value' can be a string, list, boolean, etc.
    """
    # Allow arbitrary types for the 'value' field, which resolves the startup error.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    flag: str
    description: Optional[str] = None
    value: Optional[Any] = None
    requiresValue: Optional[bool] = False

class ToolExecutionRequest(BaseModel):
    """
    A request to execute a single tool with its specific parameters.
    """
    name: str = Field(..., description="The name of the tool to execute (e.g., 'nuclei')")
    parameters: List[ToolParameter] = Field(default_factory=list)

class ScanRequest(BaseModel):
    """
    The main request body for initiating a scan.
    """
    target: str = Field(..., description="The target IP address, hostname, or URL")
    tools: List[ToolExecutionRequest] = Field(..., description="List of tools and their parameters to run")
    scan_id: str = Field(..., description="A unique identifier for this scan")

    @validator('target')
    def target_must_be_valid(cls, v):
        if not v or not v.strip():
            raise ValueError('Target cannot be empty')
        return v.strip()

class ToolOutput(BaseModel):
    """
    Represents the output from a single tool's execution.
    """
    tool_name: str
    command: List[str]
    return_code: int
    stdout: str
    stderr: str
    output_file_paths: List[str] = Field(default_factory=list)
    success: bool

class ScanResponse(BaseModel):
    """
    Represents the final, comprehensive result of a full scan.
    """
    scan_id: str
    target: str
    target_domain: Optional[str] = None
    results: List[ToolOutput]
    message: str
    status: str

