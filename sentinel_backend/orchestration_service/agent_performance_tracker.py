"""
Agent Performance Tracking System

Tracks and manages performance metrics for each agent type,
enabling intelligent routing based on historical performance.
"""

import json
import time
from typing import Dict, List, Optional, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import statistics
import asyncio
from pathlib import Path


@dataclass
class PerformanceMetric:
    """Performance metric for a single agent execution"""
    agent_type: str
    language: str  # "rust" or "python"
    execution_time_ms: float
    test_cases_generated: int
    success: bool
    timestamp: datetime
    spec_id: Optional[int] = None
    error: Optional[str] = None
    
    def efficiency_score(self) -> float:
        """Calculate efficiency score (tests per ms)"""
        if self.execution_time_ms == 0 or not self.success:
            return 0.0
        return self.test_cases_generated / self.execution_time_ms


class AgentPerformanceTracker:
    """
    Tracks agent performance and determines optimal execution strategy
    based on historical data.
    """
    
    def __init__(self, 
                 window_size: int = 100,
                 min_samples: int = 5,
                 performance_file: Optional[str] = None):
        """
        Initialize performance tracker.
        
        Args:
            window_size: Number of recent metrics to keep per agent
            min_samples: Minimum samples needed before making routing decisions
            performance_file: Optional file to persist metrics
        """
        self.window_size = window_size
        self.min_samples = min_samples
        self.performance_file = performance_file
        
        # Store metrics for each agent type and language
        # Structure: {agent_type: {language: deque[PerformanceMetric]}}
        self.metrics: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=window_size))
        )
        
        # Cache for performance summaries
        self.summary_cache: Dict[str, Dict] = {}
        self.cache_ttl = 60  # seconds
        self.last_cache_update = 0
        
        # Load existing metrics if file provided
        if performance_file and Path(performance_file).exists():
            self._load_metrics()
    
    def record_metric(self, metric: PerformanceMetric):
        """Record a new performance metric"""
        self.metrics[metric.agent_type][metric.language].append(metric)
        self._invalidate_cache()
        
        # Persist if file configured
        if self.performance_file:
            self._save_metrics()
    
    def get_best_performer(self, agent_type: str) -> Optional[str]:
        """
        Determine the best performing language for an agent type.
        
        Returns:
            "rust" or "python" based on performance, or None if insufficient data
        """
        rust_metrics = list(self.metrics[agent_type].get("rust", []))
        python_metrics = list(self.metrics[agent_type].get("python", []))
        
        # Need minimum samples for both to make decision
        if len(rust_metrics) < self.min_samples or len(python_metrics) < self.min_samples:
            return None
        
        # Calculate recent performance averages
        rust_perf = self._calculate_performance_score(rust_metrics[-self.min_samples:])
        python_perf = self._calculate_performance_score(python_metrics[-self.min_samples:])
        
        # Return best performer (lower time is better)
        if rust_perf["avg_time"] < python_perf["avg_time"]:
            return "rust"
        else:
            return "python"
    
    def get_performance_summary(self, agent_type: Optional[str] = None) -> Dict:
        """
        Get performance summary for agent(s).
        
        Args:
            agent_type: Specific agent or None for all agents
            
        Returns:
            Performance summary with statistics
        """
        # Check cache
        if time.time() - self.last_cache_update < self.cache_ttl:
            if agent_type:
                return self.summary_cache.get(agent_type, {})
            return self.summary_cache
        
        # Rebuild cache
        self._rebuild_summary_cache()
        
        if agent_type:
            return self.summary_cache.get(agent_type, {})
        return self.summary_cache
    
    def get_fallback_order(self, agent_type: str) -> List[str]:
        """
        Get ordered list of languages to try for an agent.
        
        Returns:
            Ordered list like ["python", "rust"] based on performance
        """
        rust_metrics = list(self.metrics[agent_type].get("rust", []))
        python_metrics = list(self.metrics[agent_type].get("python", []))
        
        # If we don't have enough data, use default order based on last benchmark
        if len(rust_metrics) < self.min_samples or len(python_metrics) < self.min_samples:
            # Default order based on comprehensive benchmark results
            default_order = {
                "Functional-Positive-Agent": ["python", "rust"],
                "Functional-Negative-Agent": ["rust", "python"],
                "Functional-Stateful-Agent": ["python", "rust"],
                "Security-Auth-Agent": ["python", "rust"],
                "Security-Injection-Agent": ["python", "rust"],
                "Performance-Planner-Agent": ["python", "rust"],
                "Data-Mocking-Agent": ["rust", "python"],
                "data-mocking": ["rust", "python"]
            }
            return default_order.get(agent_type, ["python", "rust"])
        
        # Calculate performance
        rust_perf = self._calculate_performance_score(rust_metrics[-self.min_samples:])
        python_perf = self._calculate_performance_score(python_metrics[-self.min_samples:])
        
        # Order by performance (lower time is better)
        if rust_perf["avg_time"] < python_perf["avg_time"]:
            return ["rust", "python"]
        else:
            return ["python", "rust"]
    
    def should_use_fallback(self, agent_type: str, primary_language: str) -> bool:
        """
        Determine if we should use fallback based on recent failures.
        
        Args:
            agent_type: The agent type
            primary_language: The primary language choice
            
        Returns:
            True if recent failure rate is high
        """
        metrics = list(self.metrics[agent_type].get(primary_language, []))
        
        if len(metrics) < 3:
            return False
        
        # Check recent failure rate
        recent = metrics[-5:]
        failure_rate = sum(1 for m in recent if not m.success) / len(recent)
        
        # Use fallback if failure rate > 40%
        return failure_rate > 0.4
    
    def _calculate_performance_score(self, metrics: List[PerformanceMetric]) -> Dict:
        """Calculate performance statistics for a set of metrics"""
        if not metrics:
            return {
                "avg_time": float('inf'),
                "success_rate": 0,
                "avg_tests": 0,
                "efficiency": 0
            }
        
        successful = [m for m in metrics if m.success]
        if not successful:
            return {
                "avg_time": float('inf'),
                "success_rate": 0,
                "avg_tests": 0,
                "efficiency": 0
            }
        
        times = [m.execution_time_ms for m in successful]
        tests = [m.test_cases_generated for m in successful]
        
        return {
            "avg_time": statistics.mean(times),
            "median_time": statistics.median(times),
            "std_time": statistics.stdev(times) if len(times) > 1 else 0,
            "success_rate": len(successful) / len(metrics),
            "avg_tests": statistics.mean(tests),
            "efficiency": sum(m.efficiency_score() for m in successful) / len(successful),
            "sample_size": len(metrics)
        }
    
    def _rebuild_summary_cache(self):
        """Rebuild the performance summary cache"""
        self.summary_cache = {}
        
        for agent_type in self.metrics:
            summary = {}
            
            for language in self.metrics[agent_type]:
                metrics = list(self.metrics[agent_type][language])
                if metrics:
                    summary[language] = self._calculate_performance_score(metrics)
            
            if summary:
                # Add comparison if both languages present
                if "rust" in summary and "python" in summary:
                    rust_time = summary["rust"]["avg_time"]
                    python_time = summary["python"]["avg_time"]
                    
                    if rust_time < python_time:
                        summary["winner"] = "rust"
                        summary["speedup"] = python_time / rust_time
                    else:
                        summary["winner"] = "python"
                        summary["speedup"] = rust_time / python_time
                
                self.summary_cache[agent_type] = summary
        
        self.last_cache_update = time.time()
    
    def _invalidate_cache(self):
        """Invalidate the summary cache"""
        self.last_cache_update = 0
    
    def _save_metrics(self):
        """Save metrics to file"""
        if not self.performance_file:
            return
        
        data = {}
        for agent_type in self.metrics:
            data[agent_type] = {}
            for language in self.metrics[agent_type]:
                data[agent_type][language] = [
                    {
                        **asdict(m),
                        "timestamp": m.timestamp.isoformat()
                    }
                    for m in self.metrics[agent_type][language]
                ]
        
        with open(self.performance_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_metrics(self):
        """Load metrics from file"""
        if not self.performance_file or not Path(self.performance_file).exists():
            return
        
        with open(self.performance_file, 'r') as f:
            data = json.load(f)
        
        for agent_type in data:
            for language in data[agent_type]:
                for metric_data in data[agent_type][language]:
                    metric_data["timestamp"] = datetime.fromisoformat(metric_data["timestamp"])
                    metric = PerformanceMetric(**metric_data)
                    self.metrics[agent_type][language].append(metric)


# Global performance tracker instance
_tracker_instance: Optional[AgentPerformanceTracker] = None


def get_performance_tracker() -> AgentPerformanceTracker:
    """Get or create the global performance tracker instance"""
    global _tracker_instance
    if _tracker_instance is None:
        # Use a persistent file for metrics
        metrics_file = Path(__file__).parent / "agent_performance_metrics.json"
        _tracker_instance = AgentPerformanceTracker(
            window_size=100,
            min_samples=5,
            performance_file=str(metrics_file)
        )
    return _tracker_instance


async def track_agent_execution(agent_type: str, 
                                language: str,
                                spec_id: Optional[int] = None):
    """
    Context manager for tracking agent execution performance.
    
    Usage:
        async with track_agent_execution("Functional-Positive-Agent", "rust") as tracker:
            result = await execute_agent(...)
            tracker.set_result(len(result.test_cases), success=True)
    """
    class ExecutionTracker:
        def __init__(self, agent_type: str, language: str, spec_id: Optional[int]):
            self.agent_type = agent_type
            self.language = language
            self.spec_id = spec_id
            self.start_time = None
            self.test_cases = 0
            self.success = False
            self.error = None
        
        def set_result(self, test_cases: int, success: bool, error: Optional[str] = None):
            self.test_cases = test_cases
            self.success = success
            self.error = error
        
        async def __aenter__(self):
            self.start_time = time.time()
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            execution_time = (time.time() - self.start_time) * 1000  # Convert to ms
            
            # Record the metric
            tracker = get_performance_tracker()
            metric = PerformanceMetric(
                agent_type=self.agent_type,
                language=self.language,
                execution_time_ms=execution_time,
                test_cases_generated=self.test_cases,
                success=self.success,
                timestamp=datetime.now(),
                spec_id=self.spec_id,
                error=self.error
            )
            tracker.record_metric(metric)
    
    return ExecutionTracker(agent_type, language, spec_id)