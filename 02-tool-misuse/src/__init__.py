"""
ASI02: Tool Misuse and Exploitation

A production-style implementation demonstrating OWASP ASI02 vulnerabilities
and their mitigations for agentic AI systems.
"""

__version__ = "1.0.0"

# Lazy imports to avoid circular dependencies and startup errors
def __getattr__(name):
    if name == "settings":
        from .config import settings
        return settings
    elif name == "CUSTOMER_DATABASE":
        from .data.mock_database import CUSTOMER_DATABASE
        return CUSTOMER_DATABASE
    elif name == "INTERNAL_SECRETS":
        from .data.mock_database import INTERNAL_SECRETS
        return INTERNAL_SECRETS
    elif name == "TOOL_INVOCATION_LOG":
        from .data.mock_database import TOOL_INVOCATION_LOG
        return TOOL_INVOCATION_LOG
    elif name == "PolicyEnforcementMiddleware":
        from .middleware.policy_enforcement import PolicyEnforcementMiddleware
        return PolicyEnforcementMiddleware
    elif name == "ToolPolicy":
        from .middleware.policy_enforcement import ToolPolicy
        return ToolPolicy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "settings",
    "CUSTOMER_DATABASE",
    "INTERNAL_SECRETS", 
    "TOOL_INVOCATION_LOG",
    "PolicyEnforcementMiddleware",
    "ToolPolicy",
]

