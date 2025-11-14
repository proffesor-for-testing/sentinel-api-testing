#!/usr/bin/env python3
"""
LionAGI QE Fleet Analysis Script for Sentinel Platform
Analyzes code quality, security, complexity, and test coverage
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime

# Add lionagi-qe-fleet to path
sys.path.insert(0, "/tmp/lionagi-qe-fleet/src")

from lionagi import iModel, Session
from lionagi_qe import QETask, QEOrchestrator
from lionagi_qe.agents import (
    CodeComplexityAnalyzerAgent,
    SecurityScannerAgent,
    QualityAnalyzerAgent,
    CoverageAnalyzerAgent,
)


class SentinelAnalyzer:
    """Orchestrates LionAGI QE Fleet analysis of Sentinel platform"""

    def __init__(self, base_path: str = "/workspaces/api-testing-agents"):
        self.base_path = Path(base_path)
        self.results = {}

        # Initialize model (using environment variable or default)
        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
        provider = "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "openai"
        model_name = "claude-sonnet-4-20250514" if provider == "anthropic" else "gpt-4o-mini"

        self.model = iModel(provider=provider, model=model_name, api_key=api_key)

    async def analyze_code_complexity(self) -> dict:
        """Analyze code complexity across the codebase"""
        print("\n🔍 Running Code Complexity Analysis...")

        agent = CodeComplexityAnalyzerAgent("complexity-analyzer", self.model)

        # Analyze Python backend
        backend_path = self.base_path / "sentinel_backend"
        python_files = list(backend_path.rglob("*.py"))[:10]  # Sample for demo

        task = QETask(
            task_type="analyze_complexity",
            context={
                "language": "python",
                "files": [str(f.relative_to(self.base_path)) for f in python_files],
                "base_path": str(self.base_path),
                "metrics": ["cyclomatic", "cognitive", "maintainability"]
            }
        )

        result = await agent.execute(task)
        return {
            "agent": "code-complexity",
            "timestamp": datetime.now().isoformat(),
            "analysis": result.to_dict() if hasattr(result, 'to_dict') else str(result),
            "files_analyzed": len(python_files)
        }

    async def analyze_security(self) -> dict:
        """Run security analysis on the codebase"""
        print("\n🔒 Running Security Analysis...")

        agent = SecurityScannerAgent("security-scanner", self.model)

        task = QETask(
            task_type="security_scan",
            context={
                "scan_type": "comprehensive",
                "target_path": str(self.base_path / "sentinel_backend"),
                "checks": ["sast", "dependencies", "secrets", "injection"],
                "severity_threshold": "medium"
            }
        )

        result = await agent.execute(task)
        return {
            "agent": "security-scanner",
            "timestamp": datetime.now().isoformat(),
            "analysis": result.to_dict() if hasattr(result, 'to_dict') else str(result)
        }

    async def analyze_quality_metrics(self) -> dict:
        """Analyze overall code quality metrics"""
        print("\n📊 Running Quality Metrics Analysis...")

        agent = QualityAnalyzerAgent("quality-analyzer", self.model)

        task = QETask(
            task_type="analyze_quality",
            context={
                "project_path": str(self.base_path),
                "metrics": [
                    "code_duplication",
                    "maintainability_index",
                    "technical_debt",
                    "test_quality"
                ],
                "integrations": ["sonarqube", "eslint", "pylint"]
            }
        )

        result = await agent.execute(task)
        return {
            "agent": "quality-analyzer",
            "timestamp": datetime.now().isoformat(),
            "analysis": result.to_dict() if hasattr(result, 'to_dict') else str(result)
        }

    async def analyze_test_coverage(self) -> dict:
        """Analyze test coverage and identify gaps"""
        print("\n🧪 Running Test Coverage Analysis...")

        agent = CoverageAnalyzerAgent("coverage-analyzer", self.model)

        task = QETask(
            task_type="analyze_coverage",
            context={
                "source_path": str(self.base_path / "sentinel_backend"),
                "test_path": str(self.base_path / "tests"),
                "coverage_threshold": 80,
                "identify_gaps": True,
                "frameworks": ["pytest", "jest"]
            }
        )

        result = await agent.execute(task)
        return {
            "agent": "coverage-analyzer",
            "timestamp": datetime.now().isoformat(),
            "analysis": result.to_dict() if hasattr(result, 'to_dict') else str(result)
        }

    async def run_parallel_analysis(self):
        """Run all analyses in parallel for efficiency"""
        print("🚀 Starting LionAGI QE Fleet Analysis of Sentinel Platform")
        print(f"📁 Base Path: {self.base_path}")
        print(f"🤖 Model: LionAGI iModel")

        # Run all analyses in parallel
        results = await asyncio.gather(
            self.analyze_code_complexity(),
            self.analyze_security(),
            self.analyze_quality_metrics(),
            self.analyze_test_coverage(),
            return_exceptions=True
        )

        # Collect results
        self.results = {
            "metadata": {
                "platform": "Sentinel API Testing Platform",
                "analysis_time": datetime.now().isoformat(),
                "lionagi_qe_fleet_version": "1.1.0",
                "base_path": str(self.base_path)
            },
            "analyses": {}
        }

        analysis_names = ["complexity", "security", "quality", "coverage"]
        for name, result in zip(analysis_names, results):
            if isinstance(result, Exception):
                self.results["analyses"][name] = {
                    "status": "error",
                    "error": str(result)
                }
                print(f"❌ {name} analysis failed: {result}")
            else:
                self.results["analyses"][name] = result
                print(f"✅ {name} analysis completed")

        return self.results

    def generate_report(self) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("=" * 80)
        report.append("🦁 LIONAGI QE FLEET - SENTINEL PLATFORM ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        metadata = self.results.get("metadata", {})
        report.append(f"Platform: {metadata.get('platform', 'Unknown')}")
        report.append(f"Analysis Time: {metadata.get('analysis_time', 'Unknown')}")
        report.append(f"LionAGI QE Fleet Version: {metadata.get('lionagi_qe_fleet_version', 'Unknown')}")
        report.append("")

        analyses = self.results.get("analyses", {})

        # Complexity Analysis
        if "complexity" in analyses:
            report.append("-" * 80)
            report.append("📊 CODE COMPLEXITY ANALYSIS")
            report.append("-" * 80)
            complexity = analyses["complexity"]
            report.append(f"Status: {complexity.get('status', 'completed')}")
            report.append(f"Files Analyzed: {complexity.get('files_analyzed', 0)}")
            report.append(f"Timestamp: {complexity.get('timestamp', 'Unknown')}")
            report.append("")

        # Security Analysis
        if "security" in analyses:
            report.append("-" * 80)
            report.append("🔒 SECURITY ANALYSIS")
            report.append("-" * 80)
            security = analyses["security"]
            report.append(f"Status: {security.get('status', 'completed')}")
            report.append(f"Timestamp: {security.get('timestamp', 'Unknown')}")
            report.append("")

        # Quality Metrics
        if "quality" in analyses:
            report.append("-" * 80)
            report.append("✨ QUALITY METRICS ANALYSIS")
            report.append("-" * 80)
            quality = analyses["quality"]
            report.append(f"Status: {quality.get('status', 'completed')}")
            report.append(f"Timestamp: {quality.get('timestamp', 'Unknown')}")
            report.append("")

        # Coverage Analysis
        if "coverage" in analyses:
            report.append("-" * 80)
            report.append("🧪 TEST COVERAGE ANALYSIS")
            report.append("-" * 80)
            coverage = analyses["coverage"]
            report.append(f"Status: {coverage.get('status', 'completed')}")
            report.append(f"Timestamp: {coverage.get('timestamp', 'Unknown')}")
            report.append("")

        report.append("=" * 80)
        report.append("📝 RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("")
        report.append("1. Review high complexity modules for refactoring opportunities")
        report.append("2. Address critical and high severity security findings")
        report.append("3. Improve code quality metrics in flagged areas")
        report.append("4. Increase test coverage in identified gaps")
        report.append("5. Implement continuous monitoring with LionAGI QE Fleet")
        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    async def save_results(self):
        """Save results to files"""
        output_dir = self.base_path / "docs" / "analysis"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON results
        json_path = output_dir / f"lionagi_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"📄 JSON results saved to: {json_path}")

        # Save text report
        report = self.generate_report()
        report_path = output_dir / f"lionagi_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"📄 Report saved to: {report_path}")

        # Print report to console
        print("\n" + report)


async def main():
    """Main entry point"""
    analyzer = SentinelAnalyzer()

    try:
        # Run parallel analysis
        await analyzer.run_parallel_analysis()

        # Save results
        await analyzer.save_results()

        print("\n✅ Analysis complete!")
        return 0

    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
