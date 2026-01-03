"""
Pydantic schemas for API request/response models.
"""

from typing import Optional, Literal
from pydantic import BaseModel, Field
from enum import Enum


class AgentType(str, Enum):
    """Type of agent to use."""
    VULNERABLE = "vulnerable"
    SECURE = "secure"
    BOTH = "both"


class Provider(str, Enum):
    """LLM provider."""
    OPENAI = "openai"
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"


class ExecuteRequest(BaseModel):
    """Request to execute a prompt against CrewAI agent."""
    prompt: str = Field(..., description="The user prompt to send to the agent")
    agent_type: AgentType = Field(
        default=AgentType.BOTH,
        description="Which agent(s) to use: vulnerable, secure, or both"
    )
    provider: Provider = Field(
        default=Provider.GEMINI,
        description="LLM provider to use"
    )
    model: Optional[str] = Field(
        default=None,
        description="Specific model to use (defaults to provider's default)"
    )
    api_key: str = Field(..., description="User's API key for the provider")


class ToolCall(BaseModel):
    """A tool call made by the agent."""
    tool: str
    args: str
    result: str
    blocked: bool = False
    reason: Optional[str] = None
    timestamp: str


class ThinkingStep(BaseModel):
    """A thinking/reasoning step from the agent."""
    step: int
    thought: str
    action: Optional[str] = None
    action_input: Optional[str] = None
    observation: Optional[str] = None
    timestamp: str


class PolicyAction(BaseModel):
    """A policy enforcement action."""
    tool: str
    action: Literal["allowed", "blocked", "modified"]
    reason: str
    timestamp: str


class AgentResult(BaseModel):
    """Result from a single agent execution."""
    agent_type: str
    response: str
    thinking: list[ThinkingStep] = []
    tool_calls: list[ToolCall] = []
    policy_actions: list[PolicyAction] = []
    execution_time_ms: int
    error: Optional[str] = None


class ExecuteResponse(BaseModel):
    """Response from the execute endpoint."""
    success: bool
    vulnerable_result: Optional[AgentResult] = None
    secure_result: Optional[AgentResult] = None
    comparison: Optional[dict] = None


class AttackScenarioResponse(BaseModel):
    """An attack scenario."""
    name: str
    description: str
    payload: str
    expected_vulnerable_outcome: str
    expected_secure_outcome: str


class AttacksListResponse(BaseModel):
    """List of available attack scenarios."""
    attacks: list[AttackScenarioResponse]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    crewai_available: bool


class StreamEvent(BaseModel):
    """Event for SSE streaming."""
    event: Literal["thinking", "tool_call", "policy", "result", "error", "done"]
    data: dict


