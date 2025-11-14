#!/usr/bin/env python3
"""
Simplified LionAGI QE Fleet Analysis for Sentinel Platform
Uses the correct LionAGI patterns from quick_start.py
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add lionagi-qe-fleet to path
sys.path.insert(0, "/tmp/lionagi-qe-fleet/src")

from lionagi import iModel
from lionagi_qe.core.memory import QEMemory
from lionagi_qe.core.task import QETask
from lionagi_qe.agents import (
    CodeComplexityAnalyzerAgent,
    SecurityScannerAgent,
    QualityAnalyzerAgent,
    CoverageAnalyzerAgent,
)

load_dotenv()


async def analyze_code_complexity():
    """Analyze code complexity of Sentinel backend"""
    print("\n" + "="*80)
    print("  📊 CODE COMPLEXITY ANALYSIS")
    print("="*80 + "\n")

    # Initialize agent
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()
    agent = CodeComplexityAnalyzerAgent(
        agent_id="complexity-analyzer",
        model=model,
        memory=memory
    )

    # Sample Python files from backend
    backend_path = Path("/workspaces/api-testing-agents/sentinel_backend")
    python_files = list(backend_path.rglob("*.py"))[:5]

    # Create task
    task = QETask(
        task_type="analyze_complexity",
        context={
            "language": "python",
            "files": [str(f) for f in python_files],
            "metrics": ["cyclomatic", "cognitive", "maintainability"],
            "threshold": 10
        }
    )

    # Execute
    print("🔍 Analyzing code complexity...")
    result = await agent.execute(task)

    # Display results
    print(f"\n✅ Analysis Complete!")
    print(f"   Files Analyzed: {len(python_files)}")
    if hasattr(result, 'average_complexity'):
        print(f"   Average Complexity: {result.average_complexity}")
    if hasattr(result, 'high_complexity_count'):
        print(f"   High Complexity Files: {result.high_complexity_count}")

    return {"agent": "code-complexity", "result": result, "files_count": len(python_files)}


async def analyze_security():
    """Security analysis of Sentinel backend"""
    print("\n" + "="*80)
    print("  🔒 SECURITY ANALYSIS")
    print("="*80 + "\n")

    # Initialize agent
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()
    agent = SecurityScannerAgent(
        agent_id="security-scanner",
        model=model,
        memory=memory
    )

    # Create task
    task = QETask(
        task_type="security_scan",
        context={
            "scan_type": "comprehensive",
            "target_path": "/workspaces/api-testing-agents/sentinel_backend",
            "checks": ["sql_injection", "xss", "auth", "secrets"],
            "severity_threshold": "medium"
        }
    )

    # Execute
    print("🔍 Scanning for security vulnerabilities...")
    result = await agent.execute(task)

    # Display results
    print(f"\n✅ Security Scan Complete!")
    if hasattr(result, 'vulnerabilities_found'):
        print(f"   Vulnerabilities Found: {result.vulnerabilities_found}")
    if hasattr(result, 'critical_count'):
        print(f"   Critical Issues: {result.critical_count}")

    return {"agent": "security-scanner", "result": result}


async def analyze_quality():
    """Quality metrics analysis"""
    print("\n" + "="*80)
    print("  ✨ QUALITY METRICS ANALYSIS")
    print("="*80 + "\n")

    # Initialize agent
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()
    agent = QualityAnalyzerAgent(
        agent_id="quality-analyzer",
        model=model,
        memory=memory
    )

    # Create task
    task = QETask(
        task_type="analyze_quality",
        context={
            "project_path": "/workspaces/api-testing-agents",
            "metrics": ["maintainability", "duplication", "technical_debt"],
            "integrations": ["pylint", "eslint"]
        }
    )

    # Execute
    print("🔍 Analyzing code quality metrics...")
    result = await agent.execute(task)

    # Display results
    print(f"\n✅ Quality Analysis Complete!")
    if hasattr(result, 'quality_score'):
        print(f"   Quality Score: {result.quality_score}/100")
    if hasattr(result, 'maintainability_index'):
        print(f"   Maintainability Index: {result.maintainability_index}")

    return {"agent": "quality-analyzer", "result": result}


async def analyze_coverage():
    """Test coverage analysis"""
    print("\n" + "="*80)
    print("  🧪 TEST COVERAGE ANALYSIS")
    print("="*80 + "\n")

    # Initialize agent
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()
    agent = CoverageAnalyzerAgent(
        agent_id="coverage-analyzer",
        model=model,
        memory=memory
    )

    # Sample coverage data
    coverage_data = {
        "overall": 78.5,
        "files": {
            "sentinel_backend/agents/functional_positive.py": {
                "lines": {"covered": 120, "total": 150},
                "branches": {"covered": 30, "total": 45}
            },
            "sentinel_backend/agents/security_auth.py": {
                "lines": {"covered": 95, "total": 130},
                "branches": {"covered": 25, "total": 40}
            }
        }
    }

    # Create task
    task = QETask(
        task_type="analyze_coverage",
        context={
            "coverage_data": coverage_data,
            "framework": "pytest",
            "codebase_path": "/workspaces/api-testing-agents/sentinel_backend",
            "target_coverage": 85
        }
    )

    # Execute
    print("🔍 Analyzing test coverage...")
    result = await agent.execute(task)

    # Display results
    print(f"\n✅ Coverage Analysis Complete!")
    if hasattr(result, 'overall_coverage'):
        print(f"   Overall Coverage: {result.overall_coverage}%")
    if hasattr(result, 'line_coverage'):
        print(f"   Line Coverage: {result.line_coverage}%")
    if hasattr(result, 'gaps'):
        print(f"   Coverage Gaps: {len(result.gaps)}")

    return {"agent": "coverage-analyzer", "result": result}


async def main():
    """Run all analyses"""
    print("\n" + "="*80)
    print("  🦁 LIONAGI QE FLEET - SENTINEL PLATFORM ANALYSIS")
    print("="*80)
    print("\n  Using LionAGI QE Fleet v1.1.0 to analyze Sentinel platform\n")

    results = {}
    timestamp = datetime.now().isoformat()

    try:
        # Run analyses sequentially to avoid rate limits
        print("⚡ Running analyses sequentially...")

        complexity = await analyze_code_complexity()
        results["complexity"] = complexity

        security = await analyze_security()
        results["security"] = security

        quality = await analyze_quality()
        results["quality"] = quality

        coverage = await analyze_coverage()
        results["coverage"] = coverage

        # Save results
        output_dir = Path("/workspaces/api-testing-agents/docs/analysis")
        output_dir.mkdir(parents=True, exist_ok=True)

        result_file = output_dir / f"lionagi_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(result_file, "w") as f:
            json.dump({
                "timestamp": timestamp,
                "platform": "Sentinel API Testing Platform",
                "lionagi_version": "1.1.0",
                "results": {
                    k: {
                        "agent": v.get("agent"),
                        "status": "completed",
                        "result_type": type(v.get("result")).__name__
                    }
                    for k, v in results.items()
                }
            }, f, indent=2, default=str)

        print(f"\n📄 Results saved to: {result_file}")

        # Summary
        print("\n" + "="*80)
        print("  ✅ ANALYSIS COMPLETE - SUMMARY")
        print("="*80)
        print(f"\n  Timestamp: {timestamp}")
        print(f"  Agents Executed: {len(results)}")
        print(f"  Platform: Sentinel API Testing Platform")
        print("\n  Analysis Results:")
        for name, data in results.items():
            print(f"    ✓ {name}: {data.get('agent')} completed")

        print("\n" + "="*80)
        print("  📝 RECOMMENDATIONS")
        print("="*80)
        print("\n  1. Review code complexity findings for refactoring opportunities")
        print("  2. Address security vulnerabilities identified in the scan")
        print("  3. Improve quality metrics in flagged areas")
        print("  4. Increase test coverage to reach 85%+ target")
        print("  5. Integrate LionAGI QE Fleet into CI/CD pipeline")
        print()

        return 0

    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
