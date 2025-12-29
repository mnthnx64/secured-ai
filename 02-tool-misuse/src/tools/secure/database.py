"""
Secure database query tool with policy enforcement.

MITIGATIONS:
- Only returns safe fields (no SSN, no passwords)
- Query validation
- Output filtering for sensitive data
"""

import json
from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field

from ...data.mock_database import CUSTOMER_DATABASE, get_safe_customer_fields


class SecureDatabaseQueryTool(BaseTool):
    """
    Secure database query tool with policy enforcement.
    
    ✅ MITIGATIONS:
    - Only returns name and email (no PII)
    - Query validation via policy middleware
    - Output filtering for sensitive patterns
    """
    
    name: str = "database_query"
    description: str = (
        "Query customer database. "
        "Only SELECT name, email, or id fields allowed."
    )
    policy_middleware: Optional[Any] = Field(default=None, exclude=True)
    
    def _run(self, query: str) -> str:
        """
        Execute a secure database query.
        
        Args:
            query: SQL-like query string
            
        Returns:
            JSON string with safe results only
        """
        # Enforce policy if middleware available
        if self.policy_middleware:
            allowed, reason, _ = self.policy_middleware.enforce(
                self.name,
                query,
            )
            if not allowed:
                return f"❌ Query blocked: {reason}"
        
        # Execute query with safe field access only
        if "C00" in query:
            customer_id = next(
                (k for k in CUSTOMER_DATABASE if k in query),
                None
            )
            if customer_id:
                # Return only safe fields
                safe_data = get_safe_customer_fields(customer_id)
                if safe_data:
                    output = json.dumps(safe_data, indent=2)
                    
                    # Additional output filtering
                    if self.policy_middleware:
                        filtered, redactions = self.policy_middleware.filter_output(
                            output
                        )
                        if redactions:
                            print(f"   ⚠️ Output filtered: {redactions}")
                        return filtered
                    
                    return output
        
        return "No results found"

