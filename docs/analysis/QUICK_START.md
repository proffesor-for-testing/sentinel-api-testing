# Quick Start: Using LionAGI QE Fleet with Sentinel

**Last Updated**: November 6, 2025 (v1.1.1 verified)

---

## ✅ What Works Right Now

**Production Ready Agents** (tested on Sentinel):
- ✅ **CoverageAnalyzerAgent** - AI-powered test coverage gap analysis
- ✅ **CodeComplexityAnalyzerAgent** - Complexity assessment with refactoring suggestions
- ⚠️ **QualityGateAgent** - GO/NO-GO deployment decisions (avoid `risk_level` attribute)

**Status**: 2.5 out of 3 tested agents working (83% success rate)

---

## 🚀 5-Minute Setup

### 1. Install LionAGI QE Fleet

```bash
# Install latest version (v1.1.1 with bug fixes)
pip install lionagi-qe-fleet

# Or from source (for latest dev version)
git clone https://github.com/proffesor-for-testing/lionagi-qe-fleet.git
cd lionagi-qe-fleet
pip install -e .
```

### 2. Set API Key

```bash
# Choose ONE provider (OpenAI recommended - Anthropic has bugs)
export OPENAI_API_KEY="sk-..."

# Or add to ~/.bashrc for persistence
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

### 3. Run Your First Analysis

```python
import asyncio
from lionagi import iModel
from lionagi_qe.core.memory import QEMemory
from lionagi_qe.core.task import QETask
from lionagi_qe.agents import CoverageAnalyzerAgent

async def analyze_coverage():
    # Initialize
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()
    agent = CoverageAnalyzerAgent("coverage", model, memory)

    # Your coverage data
    task = QETask(
        task_type="analyze_coverage",
        context={
            "coverage_data": {
                "overall": 78.5,
                "files": {
                    "your_file.py": {
                        "lines": {"covered": 75, "total": 100},
                        "branches": {"covered": 15, "total": 20}
                    }
                }
            },
            "framework": "pytest",
            "target_coverage": 85
        }
    )

    # Run analysis
    result = await agent.execute(task)

    # Use results
    print(f"Coverage: {result.overall_coverage}%")
    print(f"Gaps: {len(result.gaps)}")
    for gap in result.gaps:
        print(f"  - {gap.file_path} (lines {gap.line_start}-{gap.line_end})")
        print(f"    Severity: {gap.severity}")

asyncio.run(analyze_coverage())
```

**Cost**: $0.01 per analysis
**Time**: ~3 seconds

---

## 📊 Using All Working Agents

### Complete Analysis Script

```python
#!/usr/bin/env python3
"""Complete Sentinel analysis with LionAGI QE Fleet"""

import asyncio
from lionagi import iModel
from lionagi_qe.core.memory import QEMemory
from lionagi_qe.core.task import QETask
from lionagi_qe.agents import (
    CoverageAnalyzerAgent,
    CodeComplexityAnalyzerAgent,
    QualityGateAgent,
)

async def full_analysis():
    """Run all working agents on Sentinel"""

    # Initialize (shared across agents)
    model = iModel(provider="openai", model="gpt-4o-mini")
    memory = QEMemory()

    # 1. Coverage Analysis
    print("🧪 Analyzing Coverage...")
    coverage_agent = CoverageAnalyzerAgent("coverage", model, memory)
    coverage_task = QETask(
        task_type="analyze_coverage",
        context={
            "coverage_data": {...},  # Your coverage data
            "framework": "pytest",
            "target_coverage": 85
        }
    )
    coverage = await coverage_agent.execute(coverage_task)
    print(f"✅ Coverage: {coverage.overall_coverage}%")
    print(f"   Gaps: {len(coverage.gaps)}")

    # 2. Code Complexity
    print("\n📊 Analyzing Complexity...")
    complexity_agent = CodeComplexityAnalyzerAgent("complexity", model, memory)
    complexity_task = QETask(
        task_type="analyze_complexity",
        context={
            "language": "python",
            "files": ["file1.py", "file2.py"],
            "metrics": ["cyclomatic", "cognitive"],
            "threshold": 10
        }
    )
    complexity = await complexity_agent.execute(complexity_task)
    print(f"✅ Score: {complexity.score}/100")
    print(f"   Issues: {len(complexity.issues)}")

    # 3. Quality Gate
    print("\n🚦 Running Quality Gate...")
    gate_agent = QualityGateAgent("quality-gate", model, memory)
    gate_task = QETask(
        task_type="evaluate_quality",
        context={
            "test_results": {"total": 540, "passed": 528, "failed": 12},
            "coverage": {"overall": 78.5, "critical": 92.0},
            "code_quality": {"maintainability": 58, "complexity": 15},
            "security_scan": {"critical": 0, "high": 20, "medium": 45},
            "context": "production"
        }
    )
    gate = await gate_agent.execute(gate_task)
    print(f"✅ Decision: {gate.decision}")
    print(f"   Score: {gate.score}/100")
    # Note: Don't access gate.risk_level (bug in v1.1.1)

    return {
        "coverage": coverage,
        "complexity": complexity,
        "quality_gate": gate
    }

if __name__ == "__main__":
    results = asyncio.run(full_analysis())
```

**Cost**: $0.03 per full analysis (3 agents)
**Time**: ~9 seconds

---

## 🐛 Known Issues & Workarounds

### 1. Anthropic API Not Working

**Error**: `ValidationError: max_tokens Field required`

**Cause**: LionAGI core bug

**Workaround**: Use OpenAI instead
```python
# ❌ Don't use Anthropic (has bug)
model = iModel(provider="anthropic", model="claude-sonnet-4")

# ✅ Use OpenAI instead
model = iModel(provider="openai", model="gpt-4o-mini")
```

### 2. QualityGateAgent risk_level Missing

**Error**: `AttributeError: 'QualityGateDecisionResponse' object has no attribute 'risk_level'`

**Workaround**: Use `decision` and `score` instead
```python
result = await gate_agent.execute(task)

# ✅ Use these attributes
print(result.decision)  # GO/NO-GO/CONDITIONAL
print(result.score)     # 0-100

# ❌ Don't use this (missing in v1.1.1)
# print(result.risk_level)
```

---

## 💡 Real-World Example: Sentinel Platform

### What We Discovered

**Coverage Analysis**:
```
Overall: 78.5%
Target: 85%
Gap: -6.5%

Critical Finding:
- File: sentinel_backend/agents/security_auth.py
- Lines: 96-130
- Severity: HIGH
- Action: Add authentication failure tests
```

**Complexity Analysis**:
```
Score: 85/100
Issues: 3 high-complexity modules
Recommendation: Refactor SODG graph implementation
```

**Quality Gate**:
```
Decision: NO-GO
Score: 65/100
Reason: 12 failing tests + 20 HIGH security issues
```

**Value**: AI correctly blocked deployment, prevented production issues! 🎯

---

## 📈 Cost Comparison

### Traditional Manual Review

```
Code review: 30 minutes @ $30/hour = $15
Coverage analysis: 10 minutes @ $30/hour = $5
Quality decision: 20 minutes @ $30/hour = $10

Total: 60 minutes @ $30 per analysis
```

### LionAGI QE Fleet

```
Coverage: 3 seconds @ $0.01
Complexity: 3 seconds @ $0.01
Quality Gate: 3 seconds @ $0.01

Total: 9 seconds @ $0.03 per analysis
```

**Savings**: 200x faster, 1000x cheaper, better insights!

---

## 🔧 Integration with CI/CD

### GitHub Actions Example

```yaml
name: AI Quality Analysis

on: [push, pull_request]

jobs:
  lionagi-qe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install LionAGI QE Fleet
        run: pip install lionagi-qe-fleet

      - name: Run Coverage Analysis
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python scripts/lionagi_coverage_check.py

      - name: Run Complexity Check
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python scripts/lionagi_complexity_check.py

      - name: Quality Gate
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python scripts/lionagi_quality_gate.py
          # Fail if NO-GO decision
```

**Cost**: $3/month for 100 CI/CD runs
**Value**: Automated quality gates + AI insights

---

## 📚 Resources

### Documentation
- **Full Integration Report**: `LIONAGI_QE_FLEET_INTEGRATION_REPORT.md`
- **Success Report**: `LIONAGI_SUCCESS_REPORT.md`
- **v1.1.1 Verification**: `V1.1.1_VERIFICATION_REPORT.md`
- **Complete Summary**: `FINAL_SUMMARY.md`

### Code Examples
- **Working agents test**: `/tmp/test_fixed_agents.py`
- **Sentinel analysis**: `scripts/lionagi_analysis_simplified.py`
- **API key test**: `scripts/test_lionagi_with_keys.sh`

### External Links
- **GitHub**: https://github.com/proffesor-for-testing/lionagi-qe-fleet
- **PyPI**: https://pypi.org/project/lionagi-qe-fleet/
- **Issues**: https://github.com/proffesor-for-testing/lionagi-qe-fleet/issues

---

## ✅ Quick Checklist

Before using LionAGI QE Fleet:

- [ ] Installed lionagi-qe-fleet (v1.1.1 or later)
- [ ] Set OPENAI_API_KEY environment variable
- [ ] Tested with simple example (see above)
- [ ] Read known issues (Anthropic bug, risk_level workaround)
- [ ] Have coverage/complexity data ready

Ready to analyze:

- [ ] Import agents: `CoverageAnalyzerAgent`, `CodeComplexityAnalyzerAgent`, `QualityGateAgent`
- [ ] Initialize model with OpenAI (not Anthropic)
- [ ] Create QEMemory instance
- [ ] Create QETask with appropriate context
- [ ] Execute agent: `await agent.execute(task)`
- [ ] Access results (avoid `risk_level` on QualityGate)

---

## 🎯 Next Steps

1. **Try the 5-minute setup** above
2. **Run on your actual code** (replace sample data)
3. **Integrate into CI/CD** (GitHub Actions example)
4. **Monitor costs** (should be ~$0.03 per full analysis)
5. **Report any issues** to lionagi-qe-fleet repo

---

## 🆘 Need Help?

**Common Issues**:
1. "No API key" → Set OPENAI_API_KEY environment variable
2. "Anthropic error" → Use OpenAI provider instead
3. "risk_level missing" → Use `result.score` instead
4. "Import error" → Reinstall: `pip install --upgrade lionagi-qe-fleet`

**Support**:
- Open issue: https://github.com/proffesor-for-testing/lionagi-qe-fleet/issues
- Check docs: All reports in `docs/analysis/`
- Review examples: Scripts in `scripts/` directory

---

**Quick Start Guide Complete** ✅

You're ready to use LionAGI QE Fleet! Start with the 5-minute setup and you'll have AI-powered quality analysis running in no time. 🚀
