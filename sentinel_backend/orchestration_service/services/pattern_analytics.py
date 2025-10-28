"""
Pattern Analytics Service.

Provides analytics and insights about pattern usage, effectiveness,
and impact on test generation quality.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class PatternAnalytics:
    """
    Analytics service for pattern recognition system.

    Tracks:
    - Pattern usage statistics
    - Pattern effectiveness metrics
    - Duplicate reduction metrics
    - Pattern evolution over time
    - ROI of pattern-based generation
    """

    def __init__(self):
        """Initialize pattern analytics service."""
        self.usage_history: List[Dict[str, Any]] = []
        self.metrics_cache: Dict[str, Any] = {}
        self.baseline_metrics: Optional[Dict[str, Any]] = None
        logger.info("Pattern Analytics Service initialized")

    def record_usage(
        self,
        pattern_id: str,
        test_generated: bool,
        generation_time_ms: float,
        success: bool
    ):
        """
        Record pattern usage event.

        Args:
            pattern_id: Pattern identifier
            test_generated: Whether test was successfully generated
            generation_time_ms: Time taken to generate test
            success: Whether generated test was successful
        """
        usage_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "pattern_id": pattern_id,
            "test_generated": test_generated,
            "generation_time_ms": generation_time_ms,
            "success": success
        }

        self.usage_history.append(usage_event)
        logger.debug(f"Recorded usage for pattern {pattern_id}")

    def calculate_duplicate_reduction(
        self,
        traditional_test_count: int,
        pattern_based_test_count: int,
        unique_test_count: int
    ) -> Dict[str, Any]:
        """
        Calculate duplicate reduction achieved by patterns.

        Args:
            traditional_test_count: Tests generated without patterns
            pattern_based_test_count: Tests generated with patterns
            unique_test_count: Actual unique tests needed

        Returns:
            Reduction metrics
        """
        try:
            # Calculate waste in traditional approach
            traditional_waste = max(0, traditional_test_count - unique_test_count)
            traditional_waste_percentage = (
                (traditional_waste / traditional_test_count * 100)
                if traditional_test_count > 0 else 0
            )

            # Calculate waste in pattern approach
            pattern_waste = max(0, pattern_based_test_count - unique_test_count)
            pattern_waste_percentage = (
                (pattern_waste / pattern_based_test_count * 100)
                if pattern_based_test_count > 0 else 0
            )

            # Calculate reduction
            reduction = traditional_waste - pattern_waste
            reduction_percentage = (
                ((traditional_waste_percentage - pattern_waste_percentage) / traditional_waste_percentage * 100)
                if traditional_waste_percentage > 0 else 0
            )

            metrics = {
                "traditional_approach": {
                    "total_tests": traditional_test_count,
                    "duplicate_tests": traditional_waste,
                    "waste_percentage": traditional_waste_percentage
                },
                "pattern_approach": {
                    "total_tests": pattern_based_test_count,
                    "duplicate_tests": pattern_waste,
                    "waste_percentage": pattern_waste_percentage
                },
                "reduction": {
                    "absolute_reduction": reduction,
                    "percentage_reduction": reduction_percentage,
                    "efficiency_gain": reduction_percentage
                },
                "unique_tests_needed": unique_test_count
            }

            logger.info(
                f"Duplicate reduction: {reduction_percentage:.1f}% "
                f"({reduction} fewer duplicates)"
            )

            return metrics

        except Exception as e:
            logger.error(f"Error calculating duplicate reduction: {e}")
            return {}

    def get_pattern_effectiveness_report(
        self,
        pattern_id: Optional[str] = None,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Generate effectiveness report for patterns.

        Args:
            pattern_id: Optional specific pattern ID
            time_window_hours: Time window for analysis

        Returns:
            Effectiveness report
        """
        try:
            # Filter usage history by time window
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            recent_usage = [
                event for event in self.usage_history
                if datetime.fromisoformat(event["timestamp"]) >= cutoff_time
            ]

            # Filter by pattern if specified
            if pattern_id:
                recent_usage = [
                    event for event in recent_usage
                    if event["pattern_id"] == pattern_id
                ]

            if not recent_usage:
                return {
                    "pattern_id": pattern_id,
                    "usage_count": 0,
                    "message": "No usage data in specified time window"
                }

            # Calculate metrics
            total_usage = len(recent_usage)
            successful_generation = sum(
                1 for e in recent_usage if e["test_generated"]
            )
            successful_tests = sum(1 for e in recent_usage if e["success"])

            avg_generation_time = (
                sum(e["generation_time_ms"] for e in recent_usage) / total_usage
            )

            report = {
                "pattern_id": pattern_id or "all_patterns",
                "time_window_hours": time_window_hours,
                "total_usage": total_usage,
                "successful_generation": successful_generation,
                "generation_success_rate": (successful_generation / total_usage * 100),
                "successful_tests": successful_tests,
                "test_success_rate": (successful_tests / total_usage * 100),
                "average_generation_time_ms": avg_generation_time,
                "effectiveness_score": self._calculate_effectiveness_score(
                    successful_generation,
                    successful_tests,
                    total_usage,
                    avg_generation_time
                )
            }

            logger.info(
                f"Effectiveness report for {report['pattern_id']}: "
                f"score={report['effectiveness_score']:.2f}"
            )

            return report

        except Exception as e:
            logger.error(f"Error generating effectiveness report: {e}")
            return {}

    def get_usage_trends(
        self,
        time_window_hours: int = 168  # 1 week
    ) -> Dict[str, Any]:
        """
        Analyze usage trends over time.

        Args:
            time_window_hours: Time window for trend analysis

        Returns:
            Trend analysis results
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            recent_usage = [
                event for event in self.usage_history
                if datetime.fromisoformat(event["timestamp"]) >= cutoff_time
            ]

            if not recent_usage:
                return {"message": "No usage data in specified time window"}

            # Group by pattern
            usage_by_pattern = defaultdict(int)
            success_by_pattern = defaultdict(int)

            for event in recent_usage:
                pattern_id = event["pattern_id"]
                usage_by_pattern[pattern_id] += 1
                if event["success"]:
                    success_by_pattern[pattern_id] += 1

            # Calculate trends
            trends = {
                "time_window_hours": time_window_hours,
                "total_usage_events": len(recent_usage),
                "unique_patterns_used": len(usage_by_pattern),
                "most_used_patterns": sorted(
                    [
                        {
                            "pattern_id": pid,
                            "usage_count": count,
                            "success_count": success_by_pattern[pid],
                            "success_rate": (
                                success_by_pattern[pid] / count * 100
                            )
                        }
                        for pid, count in usage_by_pattern.items()
                    ],
                    key=lambda x: x["usage_count"],
                    reverse=True
                )[:10],  # Top 10
                "least_used_patterns": sorted(
                    [
                        {"pattern_id": pid, "usage_count": count}
                        for pid, count in usage_by_pattern.items()
                    ],
                    key=lambda x: x["usage_count"]
                )[:5]  # Bottom 5
            }

            logger.info(
                f"Usage trends: {trends['total_usage_events']} events, "
                f"{trends['unique_patterns_used']} unique patterns"
            )

            return trends

        except Exception as e:
            logger.error(f"Error analyzing usage trends: {e}")
            return {}

    def calculate_roi(
        self,
        traditional_generation_time_ms: float,
        pattern_generation_time_ms: float,
        traditional_test_count: int,
        pattern_test_count: int
    ) -> Dict[str, Any]:
        """
        Calculate ROI of pattern-based generation.

        Args:
            traditional_generation_time_ms: Time for traditional generation
            pattern_generation_time_ms: Time for pattern-based generation
            traditional_test_count: Tests from traditional method
            pattern_test_count: Tests from pattern method

        Returns:
            ROI metrics
        """
        try:
            # Time savings
            time_saved_ms = traditional_generation_time_ms - pattern_generation_time_ms
            time_saved_percentage = (
                (time_saved_ms / traditional_generation_time_ms * 100)
                if traditional_generation_time_ms > 0 else 0
            )

            # Efficiency metrics
            traditional_efficiency = (
                traditional_test_count / traditional_generation_time_ms
                if traditional_generation_time_ms > 0 else 0
            )
            pattern_efficiency = (
                pattern_test_count / pattern_generation_time_ms
                if pattern_generation_time_ms > 0 else 0
            )

            efficiency_improvement = (
                ((pattern_efficiency - traditional_efficiency) / traditional_efficiency * 100)
                if traditional_efficiency > 0 else 0
            )

            roi_metrics = {
                "time_savings": {
                    "absolute_ms": time_saved_ms,
                    "percentage": time_saved_percentage
                },
                "efficiency": {
                    "traditional_tests_per_ms": traditional_efficiency,
                    "pattern_tests_per_ms": pattern_efficiency,
                    "improvement_percentage": efficiency_improvement
                },
                "test_generation": {
                    "traditional_count": traditional_test_count,
                    "pattern_count": pattern_test_count,
                    "difference": pattern_test_count - traditional_test_count
                },
                "overall_roi_score": self._calculate_roi_score(
                    time_saved_percentage,
                    efficiency_improvement,
                    pattern_test_count,
                    traditional_test_count
                )
            }

            logger.info(
                f"ROI Analysis: {time_saved_percentage:.1f}% time saved, "
                f"{efficiency_improvement:.1f}% efficiency improvement"
            )

            return roi_metrics

        except Exception as e:
            logger.error(f"Error calculating ROI: {e}")
            return {}

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive metrics for analytics dashboard.

        Returns:
            Dashboard metrics
        """
        try:
            # Recent usage (last 24 hours)
            recent_report = self.get_pattern_effectiveness_report(time_window_hours=24)

            # Trends (last week)
            trends = self.get_usage_trends(time_window_hours=168)

            # Overall statistics
            total_events = len(self.usage_history)
            successful_events = sum(1 for e in self.usage_history if e["success"])

            dashboard = {
                "overview": {
                    "total_usage_events": total_events,
                    "successful_events": successful_events,
                    "overall_success_rate": (
                        (successful_events / total_events * 100)
                        if total_events > 0 else 0
                    )
                },
                "recent_performance": recent_report,
                "trends": trends,
                "top_performers": self._get_top_performing_patterns(5),
                "alerts": self._generate_alerts(),
                "updated_at": datetime.utcnow().isoformat()
            }

            return dashboard

        except Exception as e:
            logger.error(f"Error generating dashboard metrics: {e}")
            return {}

    def set_baseline_metrics(self, metrics: Dict[str, Any]):
        """
        Set baseline metrics for comparison.

        Args:
            metrics: Baseline metrics from traditional generation
        """
        self.baseline_metrics = {
            **metrics,
            "recorded_at": datetime.utcnow().isoformat()
        }
        logger.info("Baseline metrics set for comparison")

    def compare_to_baseline(self) -> Dict[str, Any]:
        """
        Compare current performance to baseline.

        Returns:
            Comparison results
        """
        if not self.baseline_metrics:
            return {"message": "No baseline metrics available"}

        try:
            current_metrics = self.get_pattern_effectiveness_report()

            comparison = {
                "baseline": self.baseline_metrics,
                "current": current_metrics,
                "improvements": {
                    "generation_success_rate": (
                        current_metrics.get("generation_success_rate", 0) -
                        self.baseline_metrics.get("generation_success_rate", 0)
                    ),
                    "test_success_rate": (
                        current_metrics.get("test_success_rate", 0) -
                        self.baseline_metrics.get("test_success_rate", 0)
                    ),
                    "generation_time": (
                        self.baseline_metrics.get("average_generation_time_ms", 0) -
                        current_metrics.get("average_generation_time_ms", 0)
                    )
                },
                "verdict": self._generate_comparison_verdict(current_metrics)
            }

            return comparison

        except Exception as e:
            logger.error(f"Error comparing to baseline: {e}")
            return {}

    # Helper methods

    def _calculate_effectiveness_score(
        self,
        successful_generation: int,
        successful_tests: int,
        total_usage: int,
        avg_generation_time: float
    ) -> float:
        """Calculate overall effectiveness score (0-100)."""
        if total_usage == 0:
            return 0.0

        # Weighted scoring
        generation_score = (successful_generation / total_usage) * 40
        test_score = (successful_tests / total_usage) * 40
        speed_score = min(20, 20 * (1000 / max(avg_generation_time, 1)))

        return generation_score + test_score + speed_score

    def _calculate_roi_score(
        self,
        time_saved_pct: float,
        efficiency_improvement_pct: float,
        pattern_count: int,
        traditional_count: int
    ) -> float:
        """Calculate ROI score (0-100)."""
        # Normalize and weight components
        time_component = min(40, time_saved_pct * 0.4)
        efficiency_component = min(40, efficiency_improvement_pct * 0.4)
        count_component = min(20, (pattern_count / max(traditional_count, 1)) * 20)

        return time_component + efficiency_component + count_component

    def _get_top_performing_patterns(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top performing patterns by effectiveness."""
        pattern_performance = defaultdict(lambda: {"usage": 0, "success": 0, "time": []})

        for event in self.usage_history:
            pid = event["pattern_id"]
            pattern_performance[pid]["usage"] += 1
            if event["success"]:
                pattern_performance[pid]["success"] += 1
            pattern_performance[pid]["time"].append(event["generation_time_ms"])

        # Calculate scores
        scored_patterns = []
        for pid, data in pattern_performance.items():
            success_rate = data["success"] / data["usage"] if data["usage"] > 0 else 0
            avg_time = sum(data["time"]) / len(data["time"]) if data["time"] else 0

            score = self._calculate_effectiveness_score(
                data["usage"],
                data["success"],
                data["usage"],
                avg_time
            )

            scored_patterns.append({
                "pattern_id": pid,
                "effectiveness_score": score,
                "usage_count": data["usage"],
                "success_rate": success_rate * 100,
                "average_time_ms": avg_time
            })

        # Sort by score and return top N
        scored_patterns.sort(key=lambda x: x["effectiveness_score"], reverse=True)
        return scored_patterns[:limit]

    def _generate_alerts(self) -> List[Dict[str, str]]:
        """Generate alerts based on recent patterns."""
        alerts = []

        # Check for low-performing patterns
        recent_report = self.get_pattern_effectiveness_report(time_window_hours=24)

        if recent_report.get("test_success_rate", 100) < 50:
            alerts.append({
                "level": "warning",
                "message": f"Test success rate is low: {recent_report.get('test_success_rate', 0):.1f}%",
                "recommendation": "Review failing patterns and update them"
            })

        if recent_report.get("average_generation_time_ms", 0) > 5000:
            alerts.append({
                "level": "info",
                "message": f"Average generation time is high: {recent_report.get('average_generation_time_ms', 0):.0f}ms",
                "recommendation": "Consider optimizing pattern matching algorithm"
            })

        return alerts

    def _generate_comparison_verdict(self, current_metrics: Dict[str, Any]) -> str:
        """Generate verdict comparing current to baseline."""
        if not self.baseline_metrics:
            return "No baseline for comparison"

        current_success = current_metrics.get("test_success_rate", 0)
        baseline_success = self.baseline_metrics.get("test_success_rate", 0)

        if current_success > baseline_success + 10:
            return "Significantly improved performance"
        elif current_success > baseline_success:
            return "Improved performance"
        elif current_success >= baseline_success - 5:
            return "Performance maintained"
        else:
            return "Performance degraded - review patterns"
