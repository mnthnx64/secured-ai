"""
Vulnerable database query tool.

VULNERABILITIES:
- Returns ALL fields including sensitive SSN
- No input validation
- No query restrictions
"""

import json
from datetime import datetime
from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field

from ...data.mock_database import CUSTOMER_DATABASE, log_tool_invocation


class DatabaseQueryTool(BaseTool):
    """
    Tool to query the customer database.
    
    ⚠️ VULNERABILITY: Over-scoped - returns too much data including PII.
    """
    
    name: str = "database_query"
    description: str = (
        "Query customer database. Use SQL-like syntax: "
        "SELECT fields FROM customers WHERE condition"
    )
    monitor: Optional[Any] = Field(default=None, exclude=True)
    
    def _run(self, query: str) -> str:
        """
        Execute a database query.
        
        Args:
            query: SQL-like query string
            
        Returns:
            JSON string with results
        """
        # Log to monitor if available
        if self.monitor:
            log_entry, allowed = self.monitor.log_tool_call(
                "DataOpsAgent",
                self.name,
                query,
                "",
                metadata={"query_type": "database"},
            )
            if not allowed:
                return "❌ Query blocked: Rate limit exceeded"
        
        # Log invocation for audit trail
        log_tool_invocation(self.name, {"query": query})
        
        # VULNERABILITY: Returns ALL fields including sensitive SSN
        if "*" in query or "all" in query.lower():
            return json.dumps(CUSTOMER_DATABASE, indent=2)
        
        # Simple query parsing
        if "C00" in query:
            customer_id = next(
                (k for k in CUSTOMER_DATABASE if k in query),
                None
            )
            if customer_id:
                return json.dumps(CUSTOMER_DATABASE[customer_id], indent=2)
        
        return "No results found"

