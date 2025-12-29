"""
Vulnerable HTTP request tool.

VULNERABILITIES:
- No egress controls
- Can make requests to any domain
- Data exfiltration possible
"""

from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field

from ...data.mock_database import log_tool_invocation


class HttpRequestTool(BaseTool):
    """
    Tool to make HTTP requests.
    
    ⚠️ VULNERABILITY: No egress control, no URL allowlist.
    """
    
    name: str = "http_request"
    description: str = (
        "Make an HTTP request. "
        "Parameters: url, method (GET/POST), data (optional)"
    )
    monitor: Optional[Any] = Field(default=None, exclude=True)
    
    def _run(
        self,
        url: str,
        method: str = "GET",
        data: str = "",
    ) -> str:
        """
        Make an HTTP request.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            data: Request body data
            
        Returns:
            Response status (simulated)
        """
        # Log to monitor if available
        if self.monitor:
            log_entry, allowed = self.monitor.log_tool_call(
                "DataOpsAgent",
                self.name,
                f"{method} {url}",
                data,
                extra_flags=["🌐 External HTTP request"],
                metadata={"url": url, "method": method},
            )
            if not allowed:
                return "❌ Request blocked: Rate limit exceeded"
        
        # Log invocation
        log_tool_invocation(
            self.name,
            {"url": url, "method": method, "data_length": len(data)},
        )
        
        # VULNERABILITY: No URL allowlist, data exfiltration possible
        return f"[SIMULATED] HTTP {method} to {url} - Status: 200 OK"

