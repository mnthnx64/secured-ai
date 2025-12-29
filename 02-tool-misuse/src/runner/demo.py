"""
Demo runner for ASI02 Tool Misuse scenarios.

Provides a CLI interface to run attack demonstrations
against both vulnerable and secure agents.
"""

import sys
import os
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from crewai import Task, Crew, Process

from ..agents.vulnerable_agent import (
    create_vulnerable_agent,
    print_agent_security_issues,
)
from ..agents.secure_agent import (
    create_secure_agent,
    print_agent_security_features,
)
from ..attacks.payloads import (
    ATTACK_PAYLOADS,
    get_attack_payloads_list,
    AttackScenario,
)
from ..data.mock_database import clear_invocation_log, TOOL_INVOCATION_LOG


class DemoRunner:
    """
    Runner for ASI02 Tool Misuse demonstrations.
    
    Provides methods to test attacks against vulnerable and secure agents.
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results: list[dict] = []
    
    def run_attack_against_vulnerable(
        self,
        attack: AttackScenario,
    ) -> str:
        """
        Run an attack payload against the vulnerable agent.
        
        Args:
            attack: AttackScenario to execute
            
        Returns:
            Agent response
        """
        print(f"\n{'='*60}")
        print(f"🔴 VULNERABLE AGENT: {attack.name}")
        print(f"{'='*60}")
        print(f"Description: {attack.description}")
        print(f"Expected outcome: {attack.expected_vulnerable_outcome}")
        print("-"*60)
        
        agent = create_vulnerable_agent()
        
        task = Task(
            description=f"Handle this request: {attack.payload}",
            expected_output="Respond to the request",
            agent=agent,
        )
        
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=self.verbose,
        )
        
        try:
            result = crew.kickoff()
            return str(result)
        except Exception as e:
            return f"Error: {e}"
    
    def run_attack_against_secure(
        self,
        attack: AttackScenario,
    ) -> tuple[str, dict]:
        """
        Run an attack payload against the secure agent.
        
        Args:
            attack: AttackScenario to execute
            
        Returns:
            Tuple of (agent_response, policy_summary)
        """
        print(f"\n{'='*60}")
        print(f"🟢 SECURE AGENT: {attack.name}")
        print(f"{'='*60}")
        print(f"Description: {attack.description}")
        print(f"Expected outcome: {attack.expected_secure_outcome}")
        print("-"*60)
        
        agent, policy_middleware = create_secure_agent()
        
        task = Task(
            description=f"Handle this request: {attack.payload}",
            expected_output="Respond to the request",
            agent=agent,
        )
        
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=self.verbose,
        )
        
        try:
            result = crew.kickoff()
            summary = policy_middleware.get_summary()
            return str(result), summary
        except Exception as e:
            summary = policy_middleware.get_summary()
            return f"Error: {e}", summary
    
    def run_comparison(
        self,
        attack: AttackScenario,
    ) -> dict:
        """
        Run the same attack against both agents and compare results.
        
        Args:
            attack: AttackScenario to test
            
        Returns:
            Comparison results dict
        """
        clear_invocation_log()
        
        # Run against vulnerable agent
        vuln_result = self.run_attack_against_vulnerable(attack)
        vuln_invocations = len(TOOL_INVOCATION_LOG)
        
        clear_invocation_log()
        
        # Run against secure agent
        secure_result, policy_summary = self.run_attack_against_secure(attack)
        secure_invocations = len(TOOL_INVOCATION_LOG)
        
        # Determine if attack was blocked
        blocked = (
            "blocked" in secure_result.lower()
            or "denied" in secure_result.lower()
            or policy_summary["blocked_count"] > 0
        )
        
        result = {
            "attack": attack.name,
            "vulnerable_result": vuln_result[:200],
            "vulnerable_invocations": vuln_invocations,
            "secure_result": secure_result[:200],
            "secure_invocations": secure_invocations,
            "blocked": blocked,
            "policy_summary": policy_summary,
        }
        
        self.results.append(result)
        return result
    
    def run_all_attacks(self) -> list[dict]:
        """
        Run all attack scenarios against both agents.
        
        Returns:
            List of comparison results
        """
        print("\n" + "="*60)
        print("🧪 RUNNING ALL ATTACK SCENARIOS")
        print("="*60)
        
        attacks = get_attack_payloads_list()
        
        for attack in attacks:
            self.run_comparison(attack)
        
        return self.results
    
    def print_summary(self) -> None:
        """Print a summary of all test results."""
        print("\n" + "="*60)
        print("📊 ATTACK COMPARISON SUMMARY")
        print("="*60)
        
        blocked_count = sum(1 for r in self.results if r["blocked"])
        total = len(self.results)
        
        print(f"\nTotal attacks tested: {total}")
        print(f"Attacks blocked by secure agent: {blocked_count}/{total}")
        
        print("\n" + "-"*60)
        for result in self.results:
            status = "🛡️ BLOCKED" if result["blocked"] else "⚠️ PARTIAL"
            print(f"{status} | {result['attack']}")
            if result["policy_summary"]["blocked_actions"]:
                for action in result["policy_summary"]["blocked_actions"][:2]:
                    print(f"         └─ {action['tool']}: {action['reason']}")


def run_demo(
    attack_name: Optional[str] = None,
    secure_only: bool = False,
    vulnerable_only: bool = False,
) -> None:
    """
    Run the ASI02 demo.
    
    Args:
        attack_name: Specific attack to run (or None for all)
        secure_only: Only test against secure agent
        vulnerable_only: Only test against vulnerable agent
    """
    runner = DemoRunner(verbose=True)
    
    if attack_name:
        attack = ATTACK_PAYLOADS.get(attack_name)
        if not attack:
            print(f"❌ Unknown attack: {attack_name}")
            print(f"Available attacks: {list(ATTACK_PAYLOADS.keys())}")
            return
        
        if vulnerable_only:
            runner.run_attack_against_vulnerable(attack)
        elif secure_only:
            runner.run_attack_against_secure(attack)
        else:
            runner.run_comparison(attack)
    else:
        runner.run_all_attacks()
    
    runner.print_summary()


def run_custom_prompt(
    prompt: str,
    secure_only: bool = False,
    vulnerable_only: bool = False,
) -> None:
    """
    Run a custom prompt against the agent(s).
    
    Args:
        prompt: The custom prompt to send
        secure_only: Only test against secure agent
        vulnerable_only: Only test against vulnerable agent
    """
    # Create a custom attack scenario from the prompt
    custom_attack = AttackScenario(
        name="Custom Prompt",
        description="User-provided custom prompt",
        payload=prompt,
        expected_vulnerable_outcome="Depends on prompt content",
        expected_secure_outcome="Depends on prompt content",
    )
    
    runner = DemoRunner(verbose=True)
    
    print("─" * 60)
    print("💬 CUSTOM PROMPT MODE")
    print("─" * 60)
    print(f"\nPrompt: {prompt}")
    print()
    
    if vulnerable_only:
        print("🎯 Testing against VULNERABLE agent only\n")
        runner.run_attack_against_vulnerable(custom_attack)
    elif secure_only:
        print("🎯 Testing against SECURE agent only\n")
        result, policy_summary = runner.run_attack_against_secure(custom_attack)
        
        # Print policy enforcement summary
        if policy_summary["blocked_count"] > 0:
            print("\n" + "─" * 60)
            print("🛡️ POLICY ENFORCEMENT SUMMARY")
            print("─" * 60)
            print(f"  Blocked actions: {policy_summary['blocked_count']}")
            for action in policy_summary["blocked_actions"]:
                print(f"    ✗ {action['tool']}: {action['reason']}")
    else:
        print("🎯 Testing against BOTH agents for comparison\n")
        runner.run_comparison(custom_attack)
        runner.print_summary()

