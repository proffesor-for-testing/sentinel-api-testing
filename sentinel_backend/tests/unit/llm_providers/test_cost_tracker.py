"""
Comprehensive Unit Tests for Cost Tracker

This module provides extensive test coverage for the cost tracking utilities,
including usage recording, cost calculation, and reporting.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from sentinel_backend.llm_providers.utils.cost_tracker import (
    CostTracker, UsageRecord, calculate_cost, track_usage, _global_tracker
)


class TestUsageRecord:
    """Test suite for UsageRecord dataclass"""
    
    def test_usage_record_creation(self):
        """Test creating a UsageRecord instance"""
        timestamp = datetime.now()
        record = UsageRecord(
            timestamp=timestamp,
            provider="openai",
            model="gpt-4",
            input_tokens=100,
            output_tokens=50,
            cost=0.003,
            task="test_task",
            user="test_user",
            metadata={"key": "value"}
        )
        
        assert record.timestamp == timestamp
        assert record.provider == "openai"
        assert record.model == "gpt-4"
        assert record.input_tokens == 100
        assert record.output_tokens == 50
        assert record.cost == 0.003
        assert record.task == "test_task"
        assert record.user == "test_user"
        assert record.metadata == {"key": "value"}
    
    def test_usage_record_defaults(self):
        """Test UsageRecord default values"""
        record = UsageRecord(
            timestamp=datetime.now(),
            provider="openai",
            model="gpt-4",
            input_tokens=100,
            output_tokens=50,
            cost=0.003
        )
        
        assert record.task is None
        assert record.user is None
        assert record.metadata == {}


class TestCostTracker:
    """Test suite for CostTracker class"""
    
    @pytest.fixture
    def tracker(self):
        """Create a fresh CostTracker instance"""
        return CostTracker(budget_limit=10.0)
    
    def test_initialization(self):
        """Test CostTracker initialization"""
        tracker = CostTracker(budget_limit=100.0)
        
        assert tracker.budget_limit == 100.0
        assert tracker.usage_records == []
        assert tracker.cumulative_cost == 0.0
        assert len(tracker.cost_by_model) == 0
        assert len(tracker.cost_by_provider) == 0
    
    def test_calculate_cost_known_models(self, tracker):
        """Test cost calculation for known models"""
        # GPT-4
        cost = tracker.calculate_cost("gpt-4", 1000, 500)
        expected = (1000/1000 * 0.03) + (500/1000 * 0.06)  # $0.03 + $0.03 = $0.06
        assert cost == expected
        
        # GPT-3.5-turbo
        cost = tracker.calculate_cost("gpt-3.5-turbo", 1000, 1000)
        expected = (1000/1000 * 0.0005) + (1000/1000 * 0.0015)  # $0.0005 + $0.0015 = $0.002
        assert cost == expected
        
        # Claude Opus 4.1
        cost = tracker.calculate_cost("claude-opus-4-1-20250805", 1000, 1000)
        expected = (1000/1000 * 0.015) + (1000/1000 * 0.075)  # $0.015 + $0.075 = $0.09
        assert cost == expected
        
        # Gemini 2.5 Pro
        cost = tracker.calculate_cost("gemini-2.5-pro", 1000, 1000)
        expected = (1000/1000 * 0.00125) + (1000/1000 * 0.005)  # $0.00125 + $0.005 = $0.00625
        assert cost == expected
    
    def test_calculate_cost_local_models(self, tracker):
        """Test cost calculation for local models (should be free)"""
        # Ollama models
        assert tracker.calculate_cost("ollama", 10000, 5000) == 0.0
        assert tracker.calculate_cost("vllm", 10000, 5000) == 0.0
        assert tracker.calculate_cost("local-model", 10000, 5000) == 0.0
    
    def test_calculate_cost_partial_match(self, tracker):
        """Test cost calculation with partial model name matching"""
        # Should match "gpt-4"
        cost = tracker.calculate_cost("gpt-4-custom", 1000, 500)
        assert cost > 0
        
        # Should match "claude-3-5-sonnet"
        cost = tracker.calculate_cost("claude-3-5-sonnet-custom", 1000, 1000)
        assert cost > 0
    
    def test_calculate_cost_unknown_model(self, tracker):
        """Test cost calculation for unknown models (uses default pricing)"""
        with patch('sentinel_backend.llm_providers.utils.cost_tracker.logger') as mock_logger:
            cost = tracker.calculate_cost("unknown-model", 1000, 1000)
            
            # Should use default pricing: $0.001/$0.003 per 1k tokens
            expected = (1000/1000 * 0.001) + (1000/1000 * 0.003)
            assert cost == expected
            mock_logger.warning.assert_called_once()
    
    def test_track_usage(self, tracker):
        """Test tracking LLM usage"""
        record = tracker.track_usage(
            provider="openai",
            model="gpt-4",
            input_tokens=100,
            output_tokens=50,
            task="test_task",
            user="user1",
            metadata={"session": "123"}
        )
        
        assert isinstance(record, UsageRecord)
        assert len(tracker.usage_records) == 1
        assert tracker.cumulative_cost > 0
        assert tracker.cost_by_model["gpt-4"] > 0
        assert tracker.cost_by_provider["openai"] > 0
        assert tracker.cost_by_task["test_task"] > 0
        assert tracker.cost_by_user["user1"] > 0
    
    def test_budget_limit_warning(self, tracker):
        """Test budget limit warning when exceeded"""
        tracker.budget_limit = 0.001  # Very low limit
        
        with patch('sentinel_backend.llm_providers.utils.cost_tracker.logger') as mock_logger:
            tracker.track_usage(
                provider="openai",
                model="gpt-4",
                input_tokens=1000,
                output_tokens=1000
            )
            
            # Should log warning about budget exceeded
            mock_logger.warning.assert_called_once()
            assert "Budget limit exceeded" in mock_logger.warning.call_args[0][0]
    
    def test_get_summary_all_time(self, tracker):
        """Test getting summary for all time"""
        # Track some usage
        tracker.track_usage("openai", "gpt-4", 1000, 500, task="task1")
        tracker.track_usage("anthropic", "claude-3", 500, 250, task="task2")
        
        summary = tracker.get_summary()
        
        assert summary["total_cost"] > 0
        assert summary["total_input_tokens"] == 1500
        assert summary["total_output_tokens"] == 750
        assert summary["total_requests"] == 2
        assert summary["average_cost_per_request"] > 0
        assert "gpt-4" in summary["cost_by_model"]
        assert "openai" in summary["cost_by_provider"]
        assert "task1" in summary["cost_by_task"]
    
    def test_get_summary_with_period(self, tracker):
        """Test getting summary for specific time period"""
        # Track old usage
        old_record = UsageRecord(
            timestamp=datetime.now() - timedelta(days=2),
            provider="openai",
            model="gpt-4",
            input_tokens=1000,
            output_tokens=500,
            cost=0.05
        )
        tracker.usage_records.append(old_record)
        
        # Track recent usage
        tracker.track_usage("openai", "gpt-3.5-turbo", 500, 250)
        
        # Get summary for last day
        summary = tracker.get_summary(period=timedelta(days=1))
        
        assert summary["total_requests"] == 1  # Only recent record
        assert summary["total_input_tokens"] == 500
        assert summary["total_output_tokens"] == 250
        assert "gpt-3.5-turbo" in summary["cost_by_model"]
        assert "gpt-4" not in summary["cost_by_model"]  # Old record excluded
    
    def test_get_top_spenders_by_model(self, tracker):
        """Test getting top spending models"""
        tracker.cost_by_model = {
            "gpt-4": 5.0,
            "claude-3": 3.0,
            "gpt-3.5": 1.0,
            "gemini": 0.5
        }
        
        top = tracker.get_top_spenders(n=2, by="model")
        
        assert len(top) == 2
        assert top[0] == ("gpt-4", 5.0)
        assert top[1] == ("claude-3", 3.0)
    
    def test_get_top_spenders_by_provider(self, tracker):
        """Test getting top spending providers"""
        tracker.cost_by_provider = {
            "openai": 6.0,
            "anthropic": 3.0,
            "google": 0.5
        }
        
        top = tracker.get_top_spenders(n=2, by="provider")
        
        assert len(top) == 2
        assert top[0] == ("openai", 6.0)
        assert top[1] == ("anthropic", 3.0)
    
    def test_get_top_spenders_by_task(self, tracker):
        """Test getting top spending tasks"""
        tracker.cost_by_task = {
            "analysis": 4.0,
            "generation": 2.5,
            "summarization": 1.0
        }
        
        top = tracker.get_top_spenders(n=3, by="task")
        
        assert len(top) == 3
        assert top[0] == ("analysis", 4.0)
    
    def test_get_top_spenders_invalid_category(self, tracker):
        """Test error handling for invalid category"""
        with pytest.raises(ValueError, match="Invalid grouping"):
            tracker.get_top_spenders(by="invalid")
    
    def test_export_records_json(self, tracker, tmp_path):
        """Test exporting records to JSON"""
        # Track some usage
        tracker.track_usage("openai", "gpt-4", 100, 50)
        tracker.track_usage("anthropic", "claude-3", 200, 100)
        
        # Export to JSON
        filepath = tmp_path / "usage.json"
        tracker.export_records(str(filepath), format="json")
        
        # Verify file contents
        with open(filepath, "r") as f:
            data = json.load(f)
        
        assert len(data) == 2
        assert data[0]["model"] == "gpt-4"
        assert data[1]["model"] == "claude-3"
    
    def test_export_records_csv(self, tracker, tmp_path):
        """Test exporting records to CSV"""
        import csv
        
        # Track some usage
        tracker.track_usage("openai", "gpt-4", 100, 50, task="test")
        
        # Export to CSV
        filepath = tmp_path / "usage.csv"
        tracker.export_records(str(filepath), format="csv")
        
        # Verify file contents
        with open(filepath, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        assert len(rows) == 2  # Header + 1 record
        assert rows[0][0] == "timestamp"  # Header
        assert "gpt-4" in rows[1]  # Data row
    
    def test_export_records_invalid_format(self, tracker, tmp_path):
        """Test error handling for invalid export format"""
        filepath = tmp_path / "usage.txt"
        
        with pytest.raises(ValueError, match="Unsupported format"):
            tracker.export_records(str(filepath), format="txt")
    
    def test_reset(self, tracker):
        """Test resetting tracker data"""
        # Add some data
        tracker.track_usage("openai", "gpt-4", 100, 50)
        tracker.cumulative_cost = 10.0
        tracker.cost_by_model["gpt-4"] = 5.0
        
        # Reset
        tracker.reset()
        
        assert len(tracker.usage_records) == 0
        assert tracker.cumulative_cost == 0.0
        assert len(tracker.cost_by_model) == 0
        assert len(tracker.cost_by_provider) == 0
    
    def test_budget_calculations(self, tracker):
        """Test budget-related calculations in summary"""
        tracker.budget_limit = 10.0
        tracker.cumulative_cost = 3.5
        
        summary = tracker.get_summary()
        
        assert summary["budget_remaining"] == 6.5
        assert summary["budget_percentage"] == 35.0


class TestGlobalFunctions:
    """Test suite for global tracking functions"""
    
    def test_calculate_cost_global(self):
        """Test global calculate_cost function"""
        cost = calculate_cost("gpt-4", 1000, 500)
        assert cost > 0
    
    def test_track_usage_global(self):
        """Test global track_usage function"""
        # Reset global tracker first
        _global_tracker.reset()
        
        record = track_usage(
            provider="openai",
            model="gpt-4",
            input_tokens=100,
            output_tokens=50
        )
        
        assert isinstance(record, UsageRecord)
        assert len(_global_tracker.usage_records) == 1
    
    def test_mistral_pricing(self):
        """Test Mistral model pricing"""
        tracker = CostTracker()
        
        # Mistral Large
        cost = tracker.calculate_cost("mistral-large-latest", 1000, 1000)
        expected = (1000/1000 * 0.002) + (1000/1000 * 0.006)
        assert cost == expected
        
        # Mistral Small
        cost = tracker.calculate_cost("mistral-small-latest", 1000, 1000)
        expected = (1000/1000 * 0.001) + (1000/1000 * 0.003)
        assert cost == expected
    
    def test_comprehensive_pricing_table(self):
        """Test that pricing table covers major models"""
        tracker = CostTracker()
        
        # Check that major models have pricing
        major_models = [
            "gpt-4-turbo",
            "gpt-3.5-turbo",
            "claude-opus-4-1-20250805",
            "claude-sonnet-4-20250514",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "mistral-large-latest",
            "codestral-latest"
        ]
        
        for model in major_models:
            assert model in tracker.PRICING or any(
                key in model for key in tracker.PRICING.keys()
            )
    
    def test_legacy_model_pricing(self):
        """Test pricing for legacy models"""
        tracker = CostTracker()
        
        # Legacy Gemini models (limited availability from April 2025)
        cost = tracker.calculate_cost("gemini-1.5-pro", 1000, 1000)
        assert cost > 0
        
        cost = tracker.calculate_cost("gemini-1.5-flash", 1000, 1000)
        assert cost > 0