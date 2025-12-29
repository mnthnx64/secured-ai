"""
Policy Enforcement Middleware for Tool Calls.

Implements OWASP ASI02 mitigations:
- Least privilege enforcement
- Input validation
- Output filtering
- Rate limiting
- Approval workflows
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ToolPolicy:
    """
    Policy definition for a specific tool.
    
    Attributes:
        name: Tool name this policy applies to
        allowed: Whether the tool is allowed at all
        max_calls_per_session: Rate limit for this tool
        requires_approval: Whether human approval is needed
        allowed_input_patterns: Regex patterns for allowed inputs
        blocked_input_patterns: Regex patterns for blocked inputs
        allowed_domains: Allowlist for email/HTTP domains
        max_value: Maximum value for financial operations
        sensitive_data_filter: Whether to filter PII from outputs
    """
    
    name: str
    allowed: bool = True
    max_calls_per_session: int = 10
    requires_approval: bool = False
    allowed_input_patterns: list = field(default_factory=list)
    blocked_input_patterns: list = field(default_factory=list)
    allowed_domains: list = field(default_factory=list)
    max_value: Optional[float] = None
    sensitive_data_filter: bool = True


class PolicyEnforcementMiddleware:
    """
    Intent Gate / Policy Enforcement Point (PEP) for tool calls.
    
    Implements OWASP ASI02 mitigations:
    - Least privilege enforcement
    - Input validation
    - Output filtering
    - Rate limiting
    - Approval workflows
    
    Example:
        >>> pep = PolicyEnforcementMiddleware()
        >>> pep.add_policy(ToolPolicy(
        ...     name="execute_command",
        ...     allowed=False,  # Completely disable shell access
        ... ))
        >>> allowed, reason, _ = pep.enforce("execute_command", "rm -rf /")
        >>> print(allowed)  # False
    """
    
    def __init__(self):
        self.policies: dict[str, ToolPolicy] = {}
        self.usage_counts: dict[str, int] = {}
        self.pending_approvals: list = []
        self.blocked_actions: list = []
        
        # Sensitive data patterns to filter from outputs
        self.sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b(pk_live|sk_prod|api_key)_[A-Za-z0-9]+\b',  # API keys
            r'password["\']?\s*[=:]\s*["\']?[^"\',\s]+',  # Passwords
        ]
    
    def add_policy(self, policy: ToolPolicy) -> None:
        """
        Register a policy for a tool.
        
        Args:
            policy: ToolPolicy instance to register
        """
        self.policies[policy.name] = policy
    
    def check_rate_limit(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if tool is within rate limit.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            Tuple of (allowed, reason)
        """
        policy = self.policies.get(tool_name)
        if not policy:
            return True, "No policy defined"
        
        current = self.usage_counts.get(tool_name, 0)
        if current >= policy.max_calls_per_session:
            return False, f"Rate limit exceeded ({current}/{policy.max_calls_per_session})"
        
        self.usage_counts[tool_name] = current + 1
        return True, "Within limits"
    
    def validate_input(self, tool_name: str, tool_input: str) -> tuple[bool, str]:
        """
        Validate tool input against policy.
        
        Args:
            tool_name: Name of the tool
            tool_input: Input to validate
            
        Returns:
            Tuple of (allowed, reason)
        """
        policy = self.policies.get(tool_name)
        if not policy:
            return True, "No policy"
        
        # Check blocked patterns first
        for pattern in policy.blocked_input_patterns:
            if re.search(pattern, tool_input, re.IGNORECASE):
                return False, f"Input matches blocked pattern: {pattern}"
        
        # Check allowed patterns (if specified, input must match at least one)
        if policy.allowed_input_patterns:
            for pattern in policy.allowed_input_patterns:
                if re.search(pattern, tool_input, re.IGNORECASE):
                    return True, "Input matches allowed pattern"
            return False, "Input does not match any allowed pattern"
        
        return True, "Input validated"
    
    def check_domain(self, tool_name: str, target: str) -> tuple[bool, str]:
        """
        Check if target domain/email is allowed.
        
        Args:
            tool_name: Name of the tool
            target: Target URL or email address
            
        Returns:
            Tuple of (allowed, reason)
        """
        policy = self.policies.get(tool_name)
        if not policy or not policy.allowed_domains:
            return True, "No domain restrictions"
        
        for domain in policy.allowed_domains:
            if domain in target:
                return True, f"Domain {domain} is allowed"
        
        return False, f"Domain not in allowlist: {policy.allowed_domains}"
    
    def filter_output(self, output: str) -> tuple[str, list[str]]:
        """
        Filter sensitive data from tool output.
        
        Args:
            output: Raw output string
            
        Returns:
            Tuple of (filtered_output, list_of_redactions)
        """
        filtered = output
        redactions = []
        
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern, filtered, re.IGNORECASE)
            if matches:
                redactions.append(
                    f"Redacted {len(matches)} matches for: {pattern[:20]}..."
                )
                filtered = re.sub(
                    pattern,
                    '[REDACTED]',
                    filtered,
                    flags=re.IGNORECASE,
                )
        
        return filtered, redactions
    
    def request_approval(
        self,
        tool_name: str,
        tool_input: str,
        reason: str,
    ) -> bool:
        """
        Request human approval for high-risk action.
        
        Args:
            tool_name: Name of the tool
            tool_input: Tool input
            reason: Reason approval is needed
            
        Returns:
            Whether approval was granted (False in demo)
        """
        approval_request = {
            "tool": tool_name,
            "input": tool_input[:100],
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "status": "pending",
        }
        self.pending_approvals.append(approval_request)
        
        print(f"\n🔔 APPROVAL REQUIRED")
        print(f"   Tool: {tool_name}")
        print(f"   Input: {tool_input[:50]}...")
        print(f"   Reason: {reason}")
        print(f"   [Simulating DENIED for security demo]")
        
        return False  # Auto-deny in demo
    
    def enforce(
        self,
        tool_name: str,
        tool_input: str,
        context: Optional[dict] = None,
    ) -> tuple[bool, str, str]:
        """
        Main enforcement method - check all policies.
        
        Args:
            tool_name: Name of the tool to invoke
            tool_input: Input to the tool
            context: Optional additional context
            
        Returns:
            Tuple of (allowed, reason, modified_input)
        """
        policy = self.policies.get(tool_name)
        
        # Check if tool is allowed at all
        if policy and not policy.allowed:
            self.blocked_actions.append({
                "tool": tool_name,
                "reason": "Tool not allowed",
            })
            return False, "Tool is not allowed by policy", tool_input
        
        # Check rate limit
        allowed, reason = self.check_rate_limit(tool_name)
        if not allowed:
            self.blocked_actions.append({"tool": tool_name, "reason": reason})
            return False, reason, tool_input
        
        # Validate input
        allowed, reason = self.validate_input(tool_name, tool_input)
        if not allowed:
            self.blocked_actions.append({"tool": tool_name, "reason": reason})
            return False, reason, tool_input
        
        # Check domain for email/HTTP tools
        if tool_name in ['send_email', 'http_request']:
            allowed, reason = self.check_domain(tool_name, tool_input)
            if not allowed:
                self.blocked_actions.append({"tool": tool_name, "reason": reason})
                return False, reason, tool_input
        
        # Check if approval required
        if policy and policy.requires_approval:
            approved = self.request_approval(
                tool_name,
                tool_input,
                "High-risk tool requires approval",
            )
            if not approved:
                self.blocked_actions.append({
                    "tool": tool_name,
                    "reason": "Approval denied",
                })
                return False, "Approval denied", tool_input
        
        return True, "Allowed", tool_input
    
    def reset(self) -> None:
        """Reset all usage counts and logs."""
        self.usage_counts.clear()
        self.pending_approvals.clear()
        self.blocked_actions.clear()
    
    def get_summary(self) -> dict:
        """
        Get enforcement summary.
        
        Returns:
            Summary dict with stats and blocked actions
        """
        return {
            "total_calls": sum(self.usage_counts.values()),
            "calls_by_tool": dict(self.usage_counts),
            "blocked_count": len(self.blocked_actions),
            "blocked_actions": self.blocked_actions,
            "pending_approvals": len(self.pending_approvals),
        }


def create_default_policies() -> PolicyEnforcementMiddleware:
    """
    Create a PolicyEnforcementMiddleware with secure default policies.
    
    Returns:
        Configured PolicyEnforcementMiddleware instance
    """
    pep = PolicyEnforcementMiddleware()
    
    # Database query policy
    pep.add_policy(ToolPolicy(
        name="database_query",
        max_calls_per_session=10,
        blocked_input_patterns=[
            r"SELECT\s+\*",  # Block wildcards
            r"DROP",
            r"DELETE",
        ],
        allowed_input_patterns=[
            r"SELECT\s+(name|email|id)\s+FROM",  # Only specific fields
        ],
    ))
    
    # Email policy
    pep.add_policy(ToolPolicy(
        name="send_email",
        max_calls_per_session=3,
        requires_approval=False,
        allowed_domains=["datacorp.com", "example.com"],
    ))
    
    # Shell execution policy (DISABLED)
    pep.add_policy(ToolPolicy(
        name="execute_command",
        allowed=False,
    ))
    
    # HTTP request policy
    pep.add_policy(ToolPolicy(
        name="http_request",
        max_calls_per_session=5,
        allowed_domains=["datacorp.com", "api.datacorp.internal"],
    ))
    
    # Payment policy
    pep.add_policy(ToolPolicy(
        name="process_payment",
        max_calls_per_session=1,
        requires_approval=True,
        max_value=100.0,
    ))
    
    # Delete policy (DISABLED)
    pep.add_policy(ToolPolicy(
        name="delete_record",
        allowed=False,
    ))
    
    return pep

