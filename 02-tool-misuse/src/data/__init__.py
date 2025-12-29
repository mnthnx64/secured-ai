"""Data layer for mock databases and storage."""

from .mock_database import (
    CUSTOMER_DATABASE,
    INTERNAL_SECRETS,
    TOOL_INVOCATION_LOG,
    get_customer,
    get_all_customers,
    log_tool_invocation,
)

__all__ = [
    "CUSTOMER_DATABASE",
    "INTERNAL_SECRETS",
    "TOOL_INVOCATION_LOG",
    "get_customer",
    "get_all_customers",
    "log_tool_invocation",
]

