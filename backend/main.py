"""
FastAPI Backend for SecuredAI Lab

Exposes CrewAI agents via REST API with SSE streaming for real-time
thinking, logging, and monitoring output.
"""

import os
import sys
import io
import re
import json
import asyncio
from datetime import datetime
from typing import Optional, AsyncGenerator
from contextlib import redirect_stdout, redirect_stderr

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Add the 02-tool-misuse directory to path for imports
# We add the parent so 'src' becomes a proper package and relative imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "02-tool-misuse"))

from schemas import (
    ExecuteRequest,
    ExecuteResponse,
    AgentResult,
    ThinkingStep,
    ToolCall,
    PolicyAction,
    AttackScenarioResponse,
    AttacksListResponse,
    HealthResponse,
    AgentType,
    Provider,
)

# ============================================
# App Configuration
# ============================================

app = FastAPI(
    title="SecuredAI Lab API",
    description="Backend API for CrewAI agent security demonstrations",
    version="1.0.0",
)

# CORS configuration - allow GitHub Pages and local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://mnthnx64.github.io",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:8888",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8888",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Utility Functions
# ============================================

def get_model_for_provider(provider: Provider, model: Optional[str] = None) -> str:
    """Get the model string for a given provider."""
    defaults = {
        Provider.OPENAI: "gpt-4o-mini",
        Provider.GEMINI: "gemini/gemini-2.0-flash",
        Provider.ANTHROPIC: "claude-3-haiku-20240307",
    }
    
    if model:
        # Prefix with provider if needed for CrewAI
        if provider == Provider.GEMINI and not model.startswith("gemini/"):
            return f"gemini/{model}"
        return model
    
    return defaults.get(provider, "gemini/gemini-2.0-flash")


def parse_thinking_from_output(output: str) -> list[ThinkingStep]:
    """Parse thinking steps from CrewAI verbose output."""
    thinking_steps = []
    step_num = 0
    
    # Pattern to match CrewAI thought patterns
    thought_pattern = r"(?:Thought:|Thinking:)\s*(.+?)(?=(?:Action:|Observation:|Thought:|$))"
    action_pattern = r"Action:\s*(.+?)(?=(?:Action Input:|Observation:|Thought:|$))"
    action_input_pattern = r"Action Input:\s*(.+?)(?=(?:Observation:|Thought:|$))"
    observation_pattern = r"Observation:\s*(.+?)(?=(?:Action:|Thought:|$))"
    
    # Split by thought blocks
    for thought_match in re.finditer(thought_pattern, output, re.DOTALL | re.IGNORECASE):
        step_num += 1
        thought = thought_match.group(1).strip()
        
        # Find corresponding action, input, observation
        search_start = thought_match.end()
        remaining = output[search_start:search_start + 1000]  # Look ahead
        
        action = None
        action_input = None
        observation = None
        
        action_match = re.search(action_pattern, remaining, re.DOTALL | re.IGNORECASE)
        if action_match:
            action = action_match.group(1).strip()
        
        input_match = re.search(action_input_pattern, remaining, re.DOTALL | re.IGNORECASE)
        if input_match:
            action_input = input_match.group(1).strip()
        
        obs_match = re.search(observation_pattern, remaining, re.DOTALL | re.IGNORECASE)
        if obs_match:
            observation = obs_match.group(1).strip()[:500]  # Limit observation length
        
        thinking_steps.append(ThinkingStep(
            step=step_num,
            thought=thought[:500],  # Limit thought length
            action=action,
            action_input=action_input,
            observation=observation,
            timestamp=datetime.now().isoformat(),
        ))
    
    return thinking_steps


def parse_tool_calls_from_output(output: str) -> list[ToolCall]:
    """Parse tool calls from CrewAI verbose output."""
    tool_calls = []
    
    # Pattern for tool invocations
    tool_pattern = r"(?:Using tool:|Calling:|Tool:)\s*(\w+).*?(?:with|input:|args:)\s*(.+?)(?=(?:Result:|Output:|Observation:|$))"
    result_pattern = r"(?:Result:|Output:|Observation:)\s*(.+?)(?=(?:Using tool:|Calling:|Tool:|Thought:|$))"
    
    for match in re.finditer(tool_pattern, output, re.DOTALL | re.IGNORECASE):
        tool_name = match.group(1).strip()
        args = match.group(2).strip()[:200]  # Limit args length
        
        # Find result
        search_start = match.end()
        remaining = output[search_start:search_start + 500]
        
        result = "No result captured"
        result_match = re.search(result_pattern, remaining, re.DOTALL | re.IGNORECASE)
        if result_match:
            result = result_match.group(1).strip()[:300]
        
        tool_calls.append(ToolCall(
            tool=tool_name,
            args=args,
            result=result,
            blocked=False,
            timestamp=datetime.now().isoformat(),
        ))
    
    return tool_calls


# ============================================
# CrewAI Execution
# ============================================

async def run_vulnerable_agent(prompt: str, api_key: str, provider: Provider, model: Optional[str]) -> AgentResult:
    """Run the vulnerable agent with the given prompt."""
    import time
    start_time = time.time()
    
    # Capture stdout for thinking/logs
    captured_output = io.StringIO()
    
    try:
        # Set environment variable for API key
        if provider == Provider.GEMINI:
            os.environ["GEMINI_API_KEY"] = api_key
        elif provider == Provider.OPENAI:
            os.environ["OPENAI_API_KEY"] = api_key
        elif provider == Provider.ANTHROPIC:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        
        # Override settings for the user's provider/model
        from src.config.settings import settings
        settings.llm.model = get_model_for_provider(provider, model)
        settings.llm.api_key = api_key
        
        # Import here to avoid loading CrewAI at startup
        from crewai import Task, Crew, Process
        from src.agents.vulnerable_agent import create_vulnerable_agent
        from src.data.mock_database import clear_invocation_log, TOOL_INVOCATION_LOG
        
        clear_invocation_log()
        
        agent = create_vulnerable_agent()
        
        task = Task(
            description=f"Handle this request: {prompt}",
            expected_output="Respond to the request",
            agent=agent,
        )
        
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )
        
        # Capture verbose output
        with redirect_stdout(captured_output), redirect_stderr(captured_output):
            result = crew.kickoff()
        
        output_text = captured_output.getvalue()
        execution_time = int((time.time() - start_time) * 1000)
        
        # Parse thinking and tool calls from captured output
        thinking = parse_thinking_from_output(output_text)
        tool_calls = parse_tool_calls_from_output(output_text)
        
        # Add any logged tool invocations
        for log_entry in TOOL_INVOCATION_LOG:
            tool_calls.append(ToolCall(
                tool=log_entry.get("tool", "unknown"),
                args=str(log_entry.get("input", {})),
                result=str(log_entry.get("output", ""))[:300],
                blocked=False,
                timestamp=log_entry.get("timestamp", datetime.now().isoformat()),
            ))
        
        return AgentResult(
            agent_type="vulnerable",
            response=str(result),
            thinking=thinking,
            tool_calls=tool_calls,
            policy_actions=[],
            execution_time_ms=execution_time,
        )
        
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        return AgentResult(
            agent_type="vulnerable",
            response="",
            thinking=[],
            tool_calls=[],
            policy_actions=[],
            execution_time_ms=execution_time,
            error=str(e),
        )


async def run_secure_agent(prompt: str, api_key: str, provider: Provider, model: Optional[str]) -> AgentResult:
    """Run the secure agent with policy enforcement."""
    import time
    start_time = time.time()
    
    captured_output = io.StringIO()
    
    try:
        # Set environment variable for API key
        if provider == Provider.GEMINI:
            os.environ["GEMINI_API_KEY"] = api_key
        elif provider == Provider.OPENAI:
            os.environ["OPENAI_API_KEY"] = api_key
        elif provider == Provider.ANTHROPIC:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        
        # Override settings for the user's provider/model
        from src.config.settings import settings
        settings.llm.model = get_model_for_provider(provider, model)
        settings.llm.api_key = api_key
        
        from crewai import Task, Crew, Process
        from src.agents.secure_agent import create_secure_agent
        from src.data.mock_database import clear_invocation_log, TOOL_INVOCATION_LOG
        
        clear_invocation_log()
        
        agent, policy_middleware = create_secure_agent()
        
        task = Task(
            description=f"Handle this request: {prompt}",
            expected_output="Respond to the request",
            agent=agent,
        )
        
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )
        
        with redirect_stdout(captured_output), redirect_stderr(captured_output):
            result = crew.kickoff()
        
        output_text = captured_output.getvalue()
        execution_time = int((time.time() - start_time) * 1000)
        
        # Parse thinking and tool calls
        thinking = parse_thinking_from_output(output_text)
        tool_calls = parse_tool_calls_from_output(output_text)
        
        # Add logged tool invocations
        for log_entry in TOOL_INVOCATION_LOG:
            tool_calls.append(ToolCall(
                tool=log_entry.get("tool", "unknown"),
                args=str(log_entry.get("input", {})),
                result=str(log_entry.get("output", ""))[:300],
                blocked=False,
                timestamp=log_entry.get("timestamp", datetime.now().isoformat()),
            ))
        
        # Get policy enforcement summary
        policy_summary = policy_middleware.get_summary()
        policy_actions = []
        
        for blocked in policy_summary.get("blocked_actions", []):
            policy_actions.append(PolicyAction(
                tool=blocked.get("tool", "unknown"),
                action="blocked",
                reason=blocked.get("reason", "Policy violation"),
                timestamp=datetime.now().isoformat(),
            ))
        
        return AgentResult(
            agent_type="secure",
            response=str(result),
            thinking=thinking,
            tool_calls=tool_calls,
            policy_actions=policy_actions,
            execution_time_ms=execution_time,
        )
        
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        return AgentResult(
            agent_type="secure",
            response="",
            thinking=[],
            tool_calls=[],
            policy_actions=[],
            execution_time_ms=execution_time,
            error=str(e),
        )


# ============================================
# API Endpoints
# ============================================

@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - returns API info."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        crewai_available=True,
    )


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for deployment monitoring."""
    try:
        # Try importing CrewAI to verify it's available
        import crewai
        crewai_ok = True
    except (ImportError, Exception):
        # May fail due to permission errors or missing dependencies
        crewai_ok = False
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        crewai_available=crewai_ok,
    )


@app.get("/api/attacks", response_model=AttacksListResponse)
async def list_attacks():
    """List available attack scenarios."""
    try:
        from src.attacks.payloads import ATTACK_PAYLOADS
        
        attacks = []
        for name, scenario in ATTACK_PAYLOADS.items():
            attacks.append(AttackScenarioResponse(
                name=name,
                description=scenario.description,
                payload=scenario.payload,
                expected_vulnerable_outcome=scenario.expected_vulnerable_outcome,
                expected_secure_outcome=scenario.expected_secure_outcome,
            ))
        
        return AttacksListResponse(attacks=attacks)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_prompt(request: ExecuteRequest):
    """
    Execute a prompt against CrewAI agent(s).
    
    Returns thinking steps, tool calls, policy actions, and final response.
    """
    try:
        vulnerable_result = None
        secure_result = None
        
        if request.agent_type in [AgentType.VULNERABLE, AgentType.BOTH]:
            vulnerable_result = await run_vulnerable_agent(
                prompt=request.prompt,
                api_key=request.api_key,
                provider=request.provider,
                model=request.model,
            )
        
        if request.agent_type in [AgentType.SECURE, AgentType.BOTH]:
            secure_result = await run_secure_agent(
                prompt=request.prompt,
                api_key=request.api_key,
                provider=request.provider,
                model=request.model,
            )
        
        # Build comparison if both agents ran
        comparison = None
        if vulnerable_result and secure_result:
            vuln_blocked = len([tc for tc in vulnerable_result.tool_calls if tc.blocked])
            secure_blocked = len(secure_result.policy_actions)
            
            comparison = {
                "vulnerable_tool_calls": len(vulnerable_result.tool_calls),
                "secure_tool_calls": len(secure_result.tool_calls),
                "vulnerable_blocked": vuln_blocked,
                "secure_blocked": secure_blocked,
                "attack_mitigated": secure_blocked > 0 or len(secure_result.policy_actions) > 0,
            }
        
        return ExecuteResponse(
            success=True,
            vulnerable_result=vulnerable_result,
            secure_result=secure_result,
            comparison=comparison,
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# SSE Streaming Endpoint
# ============================================

async def generate_stream(
    prompt: str,
    api_key: str,
    provider: Provider,
    model: Optional[str],
    agent_type: AgentType,
) -> AsyncGenerator[str, None]:
    """Generate SSE events for streaming execution."""
    
    try:
        yield f"data: {json.dumps({'event': 'start', 'data': {'message': 'Starting execution...'}})}\n\n"
        
        if agent_type in [AgentType.VULNERABLE, AgentType.BOTH]:
            yield f"data: {json.dumps({'event': 'status', 'data': {'agent': 'vulnerable', 'status': 'running'}})}\n\n"
            
            result = await run_vulnerable_agent(prompt, api_key, provider, model)
            
            # Stream thinking steps
            for step in result.thinking:
                yield f"data: {json.dumps({'event': 'thinking', 'data': {'agent': 'vulnerable', 'step': step.model_dump()}})}\n\n"
                await asyncio.sleep(0.1)  # Small delay for streaming effect
            
            # Stream tool calls
            for tc in result.tool_calls:
                yield f"data: {json.dumps({'event': 'tool_call', 'data': {'agent': 'vulnerable', 'tool_call': tc.model_dump()}})}\n\n"
                await asyncio.sleep(0.1)
            
            # Final result
            yield f"data: {json.dumps({'event': 'result', 'data': {'agent': 'vulnerable', 'result': result.model_dump()}})}\n\n"
        
        if agent_type in [AgentType.SECURE, AgentType.BOTH]:
            yield f"data: {json.dumps({'event': 'status', 'data': {'agent': 'secure', 'status': 'running'}})}\n\n"
            
            result = await run_secure_agent(prompt, api_key, provider, model)
            
            # Stream thinking steps
            for step in result.thinking:
                yield f"data: {json.dumps({'event': 'thinking', 'data': {'agent': 'secure', 'step': step.model_dump()}})}\n\n"
                await asyncio.sleep(0.1)
            
            # Stream tool calls
            for tc in result.tool_calls:
                yield f"data: {json.dumps({'event': 'tool_call', 'data': {'agent': 'secure', 'tool_call': tc.model_dump()}})}\n\n"
                await asyncio.sleep(0.1)
            
            # Stream policy actions
            for pa in result.policy_actions:
                yield f"data: {json.dumps({'event': 'policy', 'data': {'agent': 'secure', 'policy_action': pa.model_dump()}})}\n\n"
                await asyncio.sleep(0.1)
            
            # Final result
            yield f"data: {json.dumps({'event': 'result', 'data': {'agent': 'secure', 'result': result.model_dump()}})}\n\n"
        
        yield f"data: {json.dumps({'event': 'done', 'data': {'message': 'Execution complete'}})}\n\n"
        
    except Exception as e:
        yield f"data: {json.dumps({'event': 'error', 'data': {'message': str(e)}})}\n\n"


@app.post("/api/execute/stream")
async def execute_prompt_stream(request: ExecuteRequest):
    """
    Execute a prompt with SSE streaming.
    
    Returns a stream of events for real-time UI updates.
    """
    return StreamingResponse(
        generate_stream(
            prompt=request.prompt,
            api_key=request.api_key,
            provider=request.provider,
            model=request.model,
            agent_type=request.agent_type,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)

