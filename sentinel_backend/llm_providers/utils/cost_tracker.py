"""Cost tracking utilities for LLM usage."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


@dataclass
class UsageRecord:
    """Record of LLM usage for cost tracking."""
    timestamp: datetime
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost: float
    task: Optional[str] = None
    user: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CostTracker:
    """Track and analyze LLM usage costs."""
    
    # Pricing per 1K tokens (in USD)
    # Updated pricing as of January 2025
    PRICING = {
        # OpenAI
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        
        # Anthropic Claude
        "claude-opus-4-1-20250805": {"input": 0.015, "output": 0.075},
        "claude-opus-4-20250514": {"input": 0.015, "output": 0.075},
        "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
        "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
        "claude-3-5-haiku-20241022": {"input": 0.001, "output": 0.005},
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
        "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
        
        # Google Gemini
        "gemini-2.5-pro": {"input": 0.00125, "output": 0.005},
        "gemini-2.5-flash": {"input": 0.00025, "output": 0.001},
        "gemini-2.0-flash": {"input": 0.00025, "output": 0.001},
        # Legacy models (limited availability from April 2025)
        "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
        "gemini-1.5-flash": {"input": 0.00025, "output": 0.001},
        "gemini-pro": {"input": 0.0005, "output": 0.0015},
        
        # Mistral
        "mistral-large-latest": {"input": 0.002, "output": 0.006},
        "mistral-small-latest": {"input": 0.001, "output": 0.003},
        "codestral-latest": {"input": 0.001, "output": 0.003},
        "open-mistral-7b": {"input": 0.00025, "output": 0.00025},
        "open-mixtral-8x7b": {"input": 0.0007, "output": 0.0007},
        
        # Local models (no cost)
        "ollama": {"input": 0.0, "output": 0.0},
        "vllm": {"input": 0.0, "output": 0.0},
    }
    
    def __init__(self, budget_limit: Optional[float] = None):
        """
        Initialize cost tracker.
        
        Args:
            budget_limit: Optional spending limit in USD
        """
        self.budget_limit = budget_limit
        self.usage_records: List[UsageRecord] = []
        self.cumulative_cost = 0.0
        self.cost_by_model = defaultdict(float)
        self.cost_by_provider = defaultdict(float)
        self.cost_by_task = defaultdict(float)
        self.cost_by_user = defaultdict(float)
    
    def track_usage(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        task: Optional[str] = None,
        user: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UsageRecord:
        """
        Track LLM usage and calculate cost.
        
        Args:
            provider: Provider name
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            task: Optional task identifier
            user: Optional user identifier
            metadata: Optional metadata
            
        Returns:
            Usage record with calculated cost
        """
        # Calculate cost
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        
        # Create usage record
        record = UsageRecord(
            timestamp=datetime.now(),
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            task=task,
            user=user,
            metadata=metadata or {}
        )
        
        # Update tracking
        self.usage_records.append(record)
        self.cumulative_cost += cost
        self.cost_by_model[model] += cost
        self.cost_by_provider[provider] += cost
        
        if task:
            self.cost_by_task[task] += cost
        if user:
            self.cost_by_user[user] += cost
        
        # Check budget
        if self.budget_limit and self.cumulative_cost > self.budget_limit:
            logger.warning(
                f"Budget limit exceeded! Current: ${self.cumulative_cost:.4f}, "
                f"Limit: ${self.budget_limit:.4f}"
            )
        
        return record
    
    def calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int
    ) -> float:
        """
        Calculate cost for token usage.
        
        Args:
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        # Find pricing for model
        pricing = self.PRICING.get(model)
        
        if not pricing:
            # Try to find by partial match
            for model_key, model_pricing in self.PRICING.items():
                if model_key in model or model in model_key:
                    pricing = model_pricing
                    break
        
        if not pricing:
            # Check if it's a local model
            if any(local in model.lower() for local in ["ollama", "vllm", "local"]):
                return 0.0
            
            logger.warning(f"No pricing found for model: {model}")
            # Use a default pricing as fallback
            pricing = {"input": 0.001, "output": 0.003}
        
        # Calculate cost (pricing is per 1K tokens)
        input_cost = (input_tokens / 1000) * pricing["input"]
        output_cost = (output_tokens / 1000) * pricing["output"]
        
        return input_cost + output_cost
    
    def get_summary(self, period: Optional[timedelta] = None) -> Dict[str, Any]:
        """
        Get cost summary.
        
        Args:
            period: Optional time period to filter by
            
        Returns:
            Summary dictionary
        """
        # Filter records by period if specified
        if period:
            cutoff = datetime.now() - period
            filtered_records = [r for r in self.usage_records if r.timestamp >= cutoff]
        else:
            filtered_records = self.usage_records
        
        # Calculate period totals
        period_cost = sum(r.cost for r in filtered_records)
        period_input_tokens = sum(r.input_tokens for r in filtered_records)
        period_output_tokens = sum(r.output_tokens for r in filtered_records)
        
        # Calculate period breakdowns
        period_by_model = defaultdict(float)
        period_by_provider = defaultdict(float)
        period_by_task = defaultdict(float)
        
        for record in filtered_records:
            period_by_model[record.model] += record.cost
            period_by_provider[record.provider] += record.cost
            if record.task:
                period_by_task[record.task] += record.cost
        
        return {
            "total_cost": period_cost,
            "total_input_tokens": period_input_tokens,
            "total_output_tokens": period_output_tokens,
            "total_requests": len(filtered_records),
            "average_cost_per_request": period_cost / len(filtered_records) if filtered_records else 0,
            "cost_by_model": dict(period_by_model),
            "cost_by_provider": dict(period_by_provider),
            "cost_by_task": dict(period_by_task),
            "budget_remaining": (self.budget_limit - self.cumulative_cost) if self.budget_limit else None,
            "budget_percentage": (self.cumulative_cost / self.budget_limit * 100) if self.budget_limit else None
        }
    
    def get_top_spenders(self, n: int = 10, by: str = "model") -> List[tuple]:
        """
        Get top spending categories.
        
        Args:
            n: Number of top items to return
            by: Category to group by (model, provider, task, user)
            
        Returns:
            List of (name, cost) tuples
        """
        if by == "model":
            data = self.cost_by_model
        elif by == "provider":
            data = self.cost_by_provider
        elif by == "task":
            data = self.cost_by_task
        elif by == "user":
            data = self.cost_by_user
        else:
            raise ValueError(f"Invalid grouping: {by}")
        
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def export_records(self, filepath: str, format: str = "json"):
        """
        Export usage records to file.
        
        Args:
            filepath: Path to export file
            format: Export format (json or csv)
        """
        if format == "json":
            records_data = [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "provider": r.provider,
                    "model": r.model,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "cost": r.cost,
                    "task": r.task,
                    "user": r.user,
                    "metadata": r.metadata
                }
                for r in self.usage_records
            ]
            
            with open(filepath, "w") as f:
                json.dump(records_data, f, indent=2)
        
        elif format == "csv":
            import csv
            
            with open(filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "provider", "model", "input_tokens",
                    "output_tokens", "cost", "task", "user"
                ])
                
                for r in self.usage_records:
                    writer.writerow([
                        r.timestamp.isoformat(),
                        r.provider,
                        r.model,
                        r.input_tokens,
                        r.output_tokens,
                        r.cost,
                        r.task or "",
                        r.user or ""
                    ])
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Exported {len(self.usage_records)} records to {filepath}")
    
    def reset(self):
        """Reset all tracking data."""
        self.usage_records.clear()
        self.cumulative_cost = 0.0
        self.cost_by_model.clear()
        self.cost_by_provider.clear()
        self.cost_by_task.clear()
        self.cost_by_user.clear()


# Global cost tracker instance
_global_tracker = CostTracker()

def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate cost for token usage."""
    return _global_tracker.calculate_cost(model, input_tokens, output_tokens)

def track_usage(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    task: Optional[str] = None,
    user: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> UsageRecord:
    """Track LLM usage globally."""
    return _global_tracker.track_usage(
        provider, model, input_tokens, output_tokens, task, user, metadata
    )