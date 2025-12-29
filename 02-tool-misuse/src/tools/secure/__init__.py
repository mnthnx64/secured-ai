"""
Secure tool implementations with OWASP ASI02 mitigations.

These tools implement:
- Least privilege access
- Input validation
- Output filtering
- Rate limiting
- Approval workflows
"""

from .database import SecureDatabaseQueryTool
from .email import SecureSendEmailTool
from .payment import SecurePaymentTool


def get_all_secure_tools(policy_middleware=None) -> list:
    """
    Get all secure tools with policy middleware injection.
    
    Args:
        policy_middleware: PolicyEnforcementMiddleware instance
        
    Returns:
        List of secure tool instances
    """
    return [
        SecureDatabaseQueryTool(policy_middleware=policy_middleware),
        SecureSendEmailTool(policy_middleware=policy_middleware),
        SecurePaymentTool(policy_middleware=policy_middleware),
    ]


__all__ = [
    "SecureDatabaseQueryTool",
    "SecureSendEmailTool",
    "SecurePaymentTool",
    "get_all_secure_tools",
]

