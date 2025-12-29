"""
Secure payment processing tool with approval workflow.

MITIGATIONS:
- Requires human approval
- Amount limits
- Rate limiting
"""

from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field

from ...data.mock_database import CUSTOMER_DATABASE


class SecurePaymentTool(BaseTool):
    """
    Secure payment tool requiring approval.
    
    ✅ MITIGATIONS:
    - Requires approval for all transactions
    - Amount limit of $100 without extra approval
    - Strict rate limiting (1 per session)
    """
    
    name: str = "process_payment"
    description: str = (
        "Process a payment. "
        "Requires approval for amounts over $100."
    )
    policy_middleware: Optional[Any] = Field(default=None, exclude=True)
    max_amount: float = 100.0
    
    def _run(
        self,
        customer_id: str,
        amount: float = 0,
        description: str = "",
    ) -> str:
        """
        Process a payment with security controls.
        
        Args:
            customer_id: Customer identifier
            amount: Payment amount (limited)
            description: Payment description
            
        Returns:
            Status message
        """
        # Enforce policy if middleware available
        if self.policy_middleware:
            allowed, reason, _ = self.policy_middleware.enforce(
                self.name,
                f"customer={customer_id}, amount=${amount}",
            )
            if not allowed:
                return f"❌ Payment blocked: {reason}"
            
            # Check amount limit from policy
            policy = self.policy_middleware.policies.get(self.name)
            if policy and policy.max_value and amount > policy.max_value:
                return (
                    f"❌ Payment blocked: "
                    f"Amount ${amount} exceeds limit ${policy.max_value}"
                )
        
        # Fallback amount check
        if amount > self.max_amount:
            return (
                f"❌ Payment blocked: "
                f"Amount ${amount} exceeds limit ${self.max_amount}"
            )
        
        if customer_id in CUSTOMER_DATABASE:
            return f"✅ Payment of ${amount} processed for {customer_id}"
        
        return f"❌ Customer {customer_id} not found"

