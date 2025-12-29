"""
Mock database for the ASI02 demo.

In a production system, this would be replaced with actual database connections.
This simulates a customer database with intentionally sensitive data to
demonstrate data exfiltration risks.
"""

from datetime import datetime
from typing import Optional


# Simulated customer database with sensitive PII
CUSTOMER_DATABASE: dict[str, dict] = {
    "C001": {
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "ssn": "123-45-6789",  # SENSITIVE: Should never be exposed
        "balance": 5000.00,
    },
    "C002": {
        "name": "Bob Smith",
        "email": "bob@example.com",
        "ssn": "987-65-4321",
        "balance": 2500.00,
    },
    "C003": {
        "name": "Charlie Brown",
        "email": "charlie@example.com",
        "ssn": "456-78-9012",
        "balance": 7500.00,
    },
}

# Internal secrets that should NEVER be accessible to agents
INTERNAL_SECRETS: dict = {
    "api_keys": {
        "payment_gateway": "pk_live_abc123xyz789",
        "cloud_storage": "sk_prod_def456uvw012",
    },
    "database_credentials": {
        "host": "prod-db.datacorp.internal",
        "password": "SuperSecretP@ssw0rd!",
    },
}

# Global invocation log for forensics
TOOL_INVOCATION_LOG: list[dict] = []


def get_customer(customer_id: str) -> Optional[dict]:
    """
    Retrieve a customer by ID.
    
    Args:
        customer_id: The customer identifier (e.g., 'C001')
        
    Returns:
        Customer data dict or None if not found
    """
    return CUSTOMER_DATABASE.get(customer_id)


def get_all_customers() -> dict[str, dict]:
    """Return all customer records (DANGEROUS - exposes all data)."""
    return CUSTOMER_DATABASE.copy()


def get_safe_customer_fields(customer_id: str) -> Optional[dict]:
    """
    Retrieve only safe (non-PII) customer fields.
    
    This is the RECOMMENDED way to access customer data.
    """
    customer = CUSTOMER_DATABASE.get(customer_id)
    if customer:
        return {
            "name": customer["name"],
            "email": customer["email"],
            # SSN and balance are intentionally excluded
        }
    return None


def log_tool_invocation(
    tool_name: str,
    input_data: dict,
    output_data: Optional[str] = None,
) -> dict:
    """
    Log a tool invocation for audit trail.
    
    Args:
        tool_name: Name of the tool invoked
        input_data: Input parameters
        output_data: Optional output/result
        
    Returns:
        The log entry created
    """
    entry = {
        "tool": tool_name,
        "input": input_data,
        "output": output_data,
        "timestamp": datetime.now().isoformat(),
    }
    TOOL_INVOCATION_LOG.append(entry)
    return entry


def clear_invocation_log() -> None:
    """Clear the invocation log (for testing)."""
    TOOL_INVOCATION_LOG.clear()

