"""
Secure agent configuration with OWASP ASI02 mitigations.

This agent implements least privilege and policy enforcement.
"""

import os
from dataclasses import dataclass
from typing import Optional

from crewai import Agent, LLM

from ..tools.secure import get_all_secure_tools
from ..middleware.policy_enforcement import (
    PolicyEnforcementMiddleware,
    create_default_policies,
)
from ..config.settings import settings


@dataclass
class SecureAgentConfig:
    """Configuration for the secure agent."""
    
    role: str = "Secure Data Operations Assistant"
    goal: str = "Help users with basic data queries within policy limits"
    backstory: str = """You are a secure data operations assistant with limited capabilities.
You can only query basic customer information (name, email).
You cannot access sensitive data, execute commands, or delete records.
All high-risk operations require human approval."""
    verbose: bool = True
    allow_delegation: bool = False


def create_secure_agent(
    config: Optional[SecureAgentConfig] = None,
    policy_middleware: Optional[PolicyEnforcementMiddleware] = None,
) -> tuple[Agent, PolicyEnforcementMiddleware]:
    """
    Create a secure agent with policy enforcement.
    
    ✅ MITIGATIONS:
    - Limited tool set (no shell, no delete)
    - Policy enforcement middleware
    - Domain allowlists
    - Amount limits on payments
    
    Args:
        config: Optional configuration override
        policy_middleware: Optional custom policy middleware
        
    Returns:
        Tuple of (Agent, PolicyEnforcementMiddleware)
    """
    if config is None:
        config = SecureAgentConfig()
    
    if policy_middleware is None:
        policy_middleware = create_default_policies()
    
    # Configure LLM
    llm = LLM(
        model=settings.llm.model,
        api_key=settings.llm.api_key or os.environ.get("GEMINI_API_KEY"),
        temperature=settings.llm.temperature,
    )
    
    # Get only secure tools with policy middleware
    secure_tools = get_all_secure_tools(policy_middleware=policy_middleware)
    
    agent = Agent(
        role=config.role,
        goal=config.goal,
        backstory=config.backstory,
        tools=secure_tools,
        verbose=config.verbose,
        allow_delegation=config.allow_delegation,
        llm=llm,
    )
    
    return agent, policy_middleware


def print_agent_security_features() -> None:
    """Print security features of the secure agent."""
    print("\n🛡️ Security Features:")
    print("   • Shell execution: DISABLED")
    print("   • Record deletion: DISABLED")
    print("   • Email domains: RESTRICTED to datacorp.com, example.com")
    print("   • Data fields: LIMITED (no SSN, no passwords)")
    print("   • Payments: REQUIRES APPROVAL, max $100")

