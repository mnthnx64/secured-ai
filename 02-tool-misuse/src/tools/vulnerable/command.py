"""
Vulnerable shell command execution tool.

VULNERABILITIES:
- No sandboxing
- No command validation
- Arbitrary code execution possible
"""

from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field

from ...data.mock_database import log_tool_invocation


class ExecuteCommandTool(BaseTool):
    """
    Tool to execute shell commands.
    
    ⚠️ VULNERABILITY: No sandboxing, no command validation.
    This is extremely dangerous in production!
    """
    
    name: str = "execute_command"
    description: str = (
        "Execute a shell command on the system. "
        "Use for file operations, network diagnostics, etc."
    )
    monitor: Optional[Any] = Field(default=None, exclude=True)
    
    def _run(self, command: str) -> str:
        """
        Execute a shell command.
        
        Args:
            command: Shell command to execute
            
        Returns:
            Command output (simulated)
        """
        # Log to monitor if available
        if self.monitor:
            log_entry, allowed = self.monitor.log_tool_call(
                "DataOpsAgent",
                self.name,
                command,
                "",
                extra_flags=["🖥️ Shell command execution"],
                metadata={"command": command},
            )
            if not allowed:
                return "❌ Command blocked: Rate limit exceeded"
        
        # Log invocation
        log_tool_invocation(self.name, {"command": command})
        
        # VULNERABILITY: No command validation
        # In a real vulnerable system, this would execute the command!
        dangerous_patterns = ["rm -rf", "curl", "wget", "nc ", "base64"]
        if any(p in command.lower() for p in dangerous_patterns):
            return f"[SIMULATED] Executed dangerous command: {command}"
        
        return f"[SIMULATED] Command executed: {command}"

