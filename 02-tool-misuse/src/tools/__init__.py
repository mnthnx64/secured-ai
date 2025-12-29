"""
Tool implementations for the ASI02 demo.

This package contains both vulnerable and secure versions of tools
to demonstrate the difference in security posture.
"""

from .vulnerable import (
    DatabaseQueryTool,
    SendEmailTool,
    ExecuteCommandTool,
    HttpRequestTool,
    ProcessPaymentTool,
    DeleteRecordTool,
    get_all_vulnerable_tools,
)

from .secure import (
    SecureDatabaseQueryTool,
    SecureSendEmailTool,
    SecurePaymentTool,
    get_all_secure_tools,
)

__all__ = [
    # Vulnerable tools
    "DatabaseQueryTool",
    "SendEmailTool",
    "ExecuteCommandTool",
    "HttpRequestTool",
    "ProcessPaymentTool",
    "DeleteRecordTool",
    "get_all_vulnerable_tools",
    # Secure tools
    "SecureDatabaseQueryTool",
    "SecureSendEmailTool",
    "SecurePaymentTool",
    "get_all_secure_tools",
]

