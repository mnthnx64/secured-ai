"""
Agent definitions for ASI02 demo.

Contains both vulnerable and secure agent configurations.
"""

from .vulnerable_agent import create_vulnerable_agent, VulnerableAgentConfig
from .secure_agent import create_secure_agent, SecureAgentConfig

__all__ = [
    "create_vulnerable_agent",
    "VulnerableAgentConfig",
    "create_secure_agent",
    "SecureAgentConfig",
]

