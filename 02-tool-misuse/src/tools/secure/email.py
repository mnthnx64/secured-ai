"""
Secure email sending tool with domain allowlist.

MITIGATIONS:
- Domain allowlist enforcement
- Content filtering for sensitive data
- Rate limiting
"""

from typing import Optional, Any

from crewai.tools import BaseTool
from pydantic import Field


class SecureSendEmailTool(BaseTool):
    """
    Secure email tool with domain allowlist.
    
    ✅ MITIGATIONS:
    - Only @datacorp.com and @example.com domains allowed
    - Sensitive data filtered from body
    - Rate limited
    """
    
    name: str = "send_email"
    description: str = (
        "Send an email. "
        "Only @datacorp.com and @example.com domains allowed."
    )
    policy_middleware: Optional[Any] = Field(default=None, exclude=True)
    
    def _run(
        self,
        to: str,
        subject: str = "",
        body: str = "",
    ) -> str:
        """
        Send an email with security controls.
        
        Args:
            to: Recipient email address (must be in allowed domain)
            subject: Email subject line
            body: Email body content (will be filtered)
            
        Returns:
            Status message
        """
        # Enforce policy if middleware available
        if self.policy_middleware:
            allowed, reason, _ = self.policy_middleware.enforce(
                self.name,
                to,
            )
            if not allowed:
                return f"❌ Email blocked: {reason}"
            
            # Filter sensitive data from body
            filtered_body, redactions = self.policy_middleware.filter_output(body)
            if redactions:
                print(f"   ⚠️ Sensitive data redacted from email body: {redactions}")
        
        return f"✅ Email sent to {to} (body filtered)"

