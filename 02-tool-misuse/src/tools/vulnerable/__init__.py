"""
Vulnerable tool implementations.

⚠️ WARNING: These tools intentionally lack security controls
to demonstrate OWASP ASI02 vulnerabilities.

DO NOT USE IN PRODUCTION.
"""

from .database import DatabaseQueryTool
from .email import SendEmailTool
from .command import ExecuteCommandTool
from .http import HttpRequestTool
from .payment import ProcessPaymentTool
from .delete import DeleteRecordTool


def get_all_vulnerable_tools(monitor=None) -> list:
    """
    Get all vulnerable tools with optional monitor injection.
    
    Args:
        monitor: Optional AgentMonitor instance for logging
        
    Returns:
        List of all vulnerable tool instances
    """
    return [
        DatabaseQueryTool(monitor=monitor),
        SendEmailTool(monitor=monitor),
        ExecuteCommandTool(monitor=monitor),
        HttpRequestTool(monitor=monitor),
        ProcessPaymentTool(monitor=monitor),
        DeleteRecordTool(monitor=monitor),
    ]


__all__ = [
    "DatabaseQueryTool",
    "SendEmailTool",
    "ExecuteCommandTool",
    "HttpRequestTool",
    "ProcessPaymentTool",
    "DeleteRecordTool",
    "get_all_vulnerable_tools",
]

