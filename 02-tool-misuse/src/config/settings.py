"""
Application settings and configuration.

This module centralizes all configuration for the ASI02 demo,
following the 12-factor app methodology.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    from dotenv import load_dotenv
    # Load environment variables (ignore if .env doesn't exist)
    load_dotenv(override=False)
except Exception:
    # dotenv may not be installed or .env may not be accessible
    pass


@dataclass
class LLMConfig:
    """Configuration for the LLM backend."""
    model: str = "gemini/gemini-2.0-flash"
    api_key: Optional[str] = field(default_factory=lambda: os.environ.get("GEMINI_API_KEY"))
    temperature: float = 0.7
    max_tokens: int = 4096


@dataclass
class ToolBudgets:
    """
    Rate limits for tool invocations.
    
    These budgets help prevent resource exhaustion and limit blast radius
    of compromised agents.
    """
    default: int = 50
    database_query: int = 20
    send_email: int = 5
    execute_command: int = 3
    process_payment: int = 2
    delete_record: int = 1
    http_request: int = 10
    
    def to_dict(self) -> dict[str, int]:
        """Convert budgets to dictionary for AgentMonitor."""
        return {
            'default': self.default,
            'database_query': self.database_query,
            'send_email': self.send_email,
            'execute_command': self.execute_command,
            'process_payment': self.process_payment,
            'delete_record': self.delete_record,
            'http_request': self.http_request,
        }


@dataclass
class MonitoringConfig:
    """Configuration for agent monitoring."""
    risk_threshold: float = 0.5
    enable_tool_budgets: bool = True
    enable_alerts: bool = True
    log_level: str = "INFO"


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    # Email domain allowlist
    allowed_email_domains: list[str] = field(default_factory=lambda: [
        "datacorp.com",
        "example.com",
    ])
    
    # HTTP egress allowlist
    allowed_http_domains: list[str] = field(default_factory=lambda: [
        "datacorp.com",
        "api.datacorp.internal",
    ])
    
    # Maximum payment amount without approval
    max_payment_without_approval: float = 100.0
    
    # Enable/disable dangerous tools
    allow_shell_execution: bool = False
    allow_record_deletion: bool = False


@dataclass
class Settings:
    """Main settings container."""
    llm: LLMConfig = field(default_factory=LLMConfig)
    tool_budgets: ToolBudgets = field(default_factory=ToolBudgets)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Agent configuration
    original_goal: str = "Help users with data queries and basic customer support"
    verbose: bool = True


# Global settings instance
settings = Settings()

