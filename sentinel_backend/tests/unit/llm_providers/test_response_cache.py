"""
Comprehensive Unit Tests for Response Cache

This module provides extensive test coverage for the response caching system,
including cache key generation, TTL management, and eviction policies.
"""

import pytest
import asyncio
import hashlib
import json
import pickle
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.llm_providers.utils.response_cache import (
    CacheKey, CachedResponse, ResponseCache, cached_response, _global_cache
)


class TestCacheKey:
    """Test suite for CacheKey class"""
    
    def test_cache_key_creation(self):
        """Test creating a CacheKey instance"""
        key = CacheKey(
            provider="openai",
            model="gpt-4",
            messages_hash="abc123",
            temperature=0.7,
            max_tokens=1000,
            tools_hash="def456"
        )
        
        assert key.provider == "openai"
        assert key.model == "gpt-4"
        assert key.messages_hash == "abc123"
        assert key.temperature == 0.7
        assert key.max_tokens == 1000
        assert key.tools_hash == "def456"
    
    def test_cache_key_to_string(self):
        """Test converting CacheKey to string"""
        key = CacheKey(
            provider="openai",
            model="gpt-4",
            messages_hash="abc123",
            temperature=0.7,
            max_tokens=1000,
            tools_hash="def456"
        )
        
        key_str = key.to_string()
        assert key_str == "openai:gpt-4:abc123:0.7:1000:def456"
        
        # Test with None values
        key2 = CacheKey(
            provider="anthropic",
            model="claude-3",
            messages_hash="xyz789",
            temperature=0.5,
            max_tokens=None,
            tools_hash=None
        )
        
        key_str2 = key2.to_string()
        assert key_str2 == "anthropic:claude-3:xyz789:0.5:none:none"
    
    def test_cache_key_from_request(self):
        """Test creating CacheKey from request parameters"""
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello"}
        ]
        
        tools = [
            {"name": "test_tool", "description": "A test tool"}
        ]
        
        key = CacheKey.from_request(
            provider="openai",
            model="gpt-4",
            messages=messages,
            temperature=0.7,
            max_tokens=1000,
            tools=tools
        )
        
        assert key.provider == "openai"
        assert key.model == "gpt-4"
        assert len(key.messages_hash) == 16  # SHA256 truncated to 16 chars
        assert key.temperature == 0.7
        assert key.max_tokens == 1000
        assert len(key.tools_hash) == 16
    
    def test_cache_key_deterministic_hashing(self):
        """Test that same messages produce same hash"""
        messages = [
            {"role": "user", "content": "Test message"}
        ]
        
        key1 = CacheKey.from_request("openai", "gpt-4", messages, 0.7)
        key2 = CacheKey.from_request("openai", "gpt-4", messages, 0.7)
        
        assert key1.messages_hash == key2.messages_hash
        assert key1.to_string() == key2.to_string()
    
    def test_cache_key_different_messages(self):
        """Test that different messages produce different hashes"""
        messages1 = [{"role": "user", "content": "Message 1"}]
        messages2 = [{"role": "user", "content": "Message 2"}]
        
        key1 = CacheKey.from_request("openai", "gpt-4", messages1, 0.7)
        key2 = CacheKey.from_request("openai", "gpt-4", messages2, 0.7)
        
        assert key1.messages_hash != key2.messages_hash
        assert key1.to_string() != key2.to_string()


class TestCachedResponse:
    """Test suite for CachedResponse class"""
    
    def test_cached_response_creation(self):
        """Test creating a CachedResponse instance"""
        response_data = {"content": "Test response"}
        timestamp = datetime.now()
        
        cached = CachedResponse(
            response=response_data,
            timestamp=timestamp,
            hit_count=5,
            cost_saved=0.05,
            time_saved=2.5
        )
        
        assert cached.response == response_data
        assert cached.timestamp == timestamp
        assert cached.hit_count == 5
        assert cached.cost_saved == 0.05
        assert cached.time_saved == 2.5
    
    def test_is_expired(self):
        """Test expiration checking"""
        # Create response 10 seconds ago
        old_timestamp = datetime.now() - timedelta(seconds=10)
        cached = CachedResponse(
            response="test",
            timestamp=old_timestamp
        )
        
        # Should be expired with 5 second TTL
        assert cached.is_expired(5) is True
        
        # Should not be expired with 20 second TTL
        assert cached.is_expired(20) is False
        
        # Fresh response should not be expired
        fresh = CachedResponse(
            response="test",
            timestamp=datetime.now()
        )
        assert fresh.is_expired(3600) is False


class TestResponseCache:
    """Test suite for ResponseCache class"""
    
    @pytest.fixture
    def cache(self):
        """Create a fresh ResponseCache instance"""
        return ResponseCache(max_size=5, ttl_seconds=60, enabled=True)
    
    def test_initialization(self):
        """Test ResponseCache initialization"""
        cache = ResponseCache(max_size=100, ttl_seconds=3600, enabled=True)
        
        assert cache.max_size == 100
        assert cache.ttl_seconds == 3600
        assert cache.enabled is True
        assert len(cache.cache) == 0
        assert cache.stats["hits"] == 0
        assert cache.stats["misses"] == 0
    
    def test_get_cache_hit(self, cache):
        """Test retrieving cached response (cache hit)"""
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        response_data = {"content": "Cached response"}
        
        # Store in cache
        cache.cache[key.to_string()] = CachedResponse(
            response=response_data,
            timestamp=datetime.now()
        )
        
        # Retrieve from cache
        result = cache.get(key)
        
        assert result == response_data
        assert cache.stats["hits"] == 1
        assert cache.stats["misses"] == 0
        assert cache.cache[key.to_string()].hit_count == 1
    
    def test_get_cache_miss(self, cache):
        """Test cache miss"""
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        
        result = cache.get(key)
        
        assert result is None
        assert cache.stats["hits"] == 0
        assert cache.stats["misses"] == 1
    
    def test_get_expired_entry(self, cache):
        """Test that expired entries are not returned"""
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        
        # Store expired entry
        old_timestamp = datetime.now() - timedelta(seconds=120)
        cache.cache[key.to_string()] = CachedResponse(
            response={"content": "Old response"},
            timestamp=old_timestamp
        )
        
        # Should return None and remove expired entry
        result = cache.get(key)
        
        assert result is None
        assert key.to_string() not in cache.cache
        assert cache.stats["misses"] == 1
    
    def test_get_disabled_cache(self):
        """Test that disabled cache always returns None"""
        cache = ResponseCache(enabled=False)
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        
        # Store something
        cache.cache[key.to_string()] = CachedResponse(
            response={"content": "Test"},
            timestamp=datetime.now()
        )
        
        # Should return None when disabled
        result = cache.get(key)
        assert result is None
    
    def test_set_cache_entry(self, cache):
        """Test storing response in cache"""
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        response = {"content": "New response"}
        
        cache.set(key, response, cost=0.05, elapsed_time=2.5)
        
        assert key.to_string() in cache.cache
        cached = cache.cache[key.to_string()]
        assert cached.response == response
        assert cached.cost_saved == 0.05
        assert cached.time_saved == 2.5
    
    def test_set_with_eviction(self, cache):
        """Test that oldest entry is evicted when cache is full"""
        # Fill cache to max size
        for i in range(5):
            key = CacheKey("openai", "gpt-4", f"hash{i}", 0.7)
            cache.set(key, {"content": f"Response {i}"})
            time.sleep(0.01)  # Ensure different timestamps
        
        assert len(cache.cache) == 5
        
        # Add one more, should evict oldest
        new_key = CacheKey("openai", "gpt-4", "hash_new", 0.7)
        cache.set(new_key, {"content": "New response"})
        
        assert len(cache.cache) == 5
        assert "openai:gpt-4:hash0:0.7:none:none" not in cache.cache
        assert new_key.to_string() in cache.cache
        assert cache.stats["evictions"] == 1
    
    def test_set_disabled_cache(self):
        """Test that disabled cache doesn't store anything"""
        cache = ResponseCache(enabled=False)
        key = CacheKey("openai", "gpt-4", "hash123", 0.7)
        
        cache.set(key, {"content": "Test"})
        
        assert len(cache.cache) == 0
    
    def test_clear_cache(self, cache):
        """Test clearing the cache"""
        # Add some entries
        for i in range(3):
            key = CacheKey("openai", "gpt-4", f"hash{i}", 0.7)
            cached = CachedResponse(
                response={"content": f"Response {i}"},
                timestamp=datetime.now(),
                hit_count=2,
                cost_saved=0.01,
                time_saved=1.0
            )
            cache.cache[key.to_string()] = cached
        
        # Clear cache
        cache.clear()
        
        assert len(cache.cache) == 0
        # Stats should be updated
        assert cache.stats["total_cost_saved"] > 0
        assert cache.stats["total_time_saved"] > 0
    
    def test_cleanup_expired(self, cache):
        """Test cleaning up expired entries"""
        now = datetime.now()
        
        # Add mix of expired and fresh entries
        expired_key = CacheKey("openai", "gpt-4", "expired", 0.7)
        cache.cache[expired_key.to_string()] = CachedResponse(
            response={"content": "Expired"},
            timestamp=now - timedelta(seconds=120),
            hit_count=1,
            cost_saved=0.01,
            time_saved=1.0
        )
        
        fresh_key = CacheKey("openai", "gpt-4", "fresh", 0.7)
        cache.cache[fresh_key.to_string()] = CachedResponse(
            response={"content": "Fresh"},
            timestamp=now
        )
        
        # Cleanup
        cache.cleanup_expired()
        
        assert expired_key.to_string() not in cache.cache
        assert fresh_key.to_string() in cache.cache
        assert cache.stats["total_cost_saved"] == 0.01
        assert cache.stats["total_time_saved"] == 1.0
    
    def test_get_stats(self, cache):
        """Test getting cache statistics"""
        # Simulate some activity
        cache.stats["hits"] = 10
        cache.stats["misses"] = 5
        cache.stats["evictions"] = 2
        cache.stats["total_cost_saved"] = 0.5
        cache.stats["total_time_saved"] = 30.0
        
        # Add a cache entry
        key = CacheKey("openai", "gpt-4", "test", 0.7)
        cache.cache[key.to_string()] = CachedResponse(
            response={},
            timestamp=datetime.now()
        )
        
        stats = cache.get_stats()
        
        assert stats["enabled"] is True
        assert stats["size"] == 1
        assert stats["max_size"] == 5
        assert stats["ttl_seconds"] == 60
        assert stats["hits"] == 10
        assert stats["misses"] == 5
        assert stats["hit_rate"] == "66.67%"
        assert stats["evictions"] == 2
        assert stats["cost_saved"] == "$0.5000"
        assert stats["time_saved"] == "30.00s"
    
    def test_save_and_load_from_disk(self, cache, tmp_path):
        """Test saving and loading cache from disk"""
        # Add some cache entries
        key1 = CacheKey("openai", "gpt-4", "hash1", 0.7)
        cache.set(key1, {"content": "Response 1"})
        
        key2 = CacheKey("anthropic", "claude-3", "hash2", 0.5)
        cache.set(key2, {"content": "Response 2"})
        
        cache.stats["hits"] = 5
        cache.stats["misses"] = 3
        
        # Save to disk
        filepath = tmp_path / "cache.pkl"
        cache.save_to_disk(str(filepath))
        
        # Create new cache and load
        new_cache = ResponseCache()
        new_cache.load_from_disk(str(filepath))
        
        assert len(new_cache.cache) == 2
        assert key1.to_string() in new_cache.cache
        assert key2.to_string() in new_cache.cache
        assert new_cache.stats["hits"] == 5
        assert new_cache.stats["misses"] == 3
    
    def test_save_load_error_handling(self, cache, tmp_path):
        """Test error handling in save/load operations"""
        # Test save error
        with patch('builtins.open', side_effect=IOError("Write error")):
            with patch('sentinel_backend.llm_providers.utils.response_cache.logger') as mock_logger:
                cache.save_to_disk("/invalid/path/cache.pkl")
                mock_logger.error.assert_called_once()
        
        # Test load error
        with patch('builtins.open', side_effect=IOError("Read error")):
            with patch('sentinel_backend.llm_providers.utils.response_cache.logger') as mock_logger:
                cache.load_from_disk("/invalid/path/cache.pkl")
                mock_logger.error.assert_called_once()


class TestCachedResponseDecorator:
    """Test suite for cached_response decorator"""
    
    @pytest.mark.asyncio
    async def test_cached_response_async_hit(self):
        """Test async function with cache hit"""
        # Setup cache with existing entry
        messages = [{"role": "user", "content": "Test"}]
        key = CacheKey.from_request("openai", "gpt-4", messages, 0.7)
        cached_data = MagicMock(content="Cached response")
        _global_cache.cache[key.to_string()] = CachedResponse(
            response=cached_data,
            timestamp=datetime.now()
        )
        
        @cached_response("openai", "gpt-4")
        async def mock_generate(**kwargs):
            return MagicMock(content="New response")
        
        # Call should return cached response
        result = await mock_generate(messages=messages, temperature=0.7)
        
        assert result == cached_data
    
    @pytest.mark.asyncio
    async def test_cached_response_async_miss(self):
        """Test async function with cache miss"""
        _global_cache.clear()
        messages = [{"role": "user", "content": "Test"}]
        
        @cached_response("openai", "gpt-4")
        async def mock_generate(**kwargs):
            response = MagicMock()
            response.content = "New response"
            response.usage = {"prompt_tokens": 10, "completion_tokens": 5}
            return response
        
        # Call should generate new response and cache it
        result = await mock_generate(messages=messages, temperature=0.7)
        
        assert result.content == "New response"
        
        # Check that response was cached
        key = CacheKey.from_request("openai", "gpt-4", messages, 0.7)
        assert key.to_string() in _global_cache.cache
    
    def test_cached_response_sync(self):
        """Test sync function caching"""
        _global_cache.clear()
        messages = [{"role": "user", "content": "Test"}]
        
        @cached_response("openai", "gpt-4")
        def mock_generate(**kwargs):
            response = MagicMock()
            response.content = "Sync response"
            response.usage = {"prompt_tokens": 10, "completion_tokens": 5}
            return response
        
        # First call
        result1 = mock_generate(messages=messages, temperature=0.7)
        assert result1.content == "Sync response"
        
        # Modify the function to return different content
        mock_generate.__wrapped__ = lambda **kwargs: MagicMock(content="Different")
        
        # Second call should still return cached
        result2 = mock_generate(messages=messages, temperature=0.7)
        assert result2.content == "Sync response"
    
    @pytest.mark.asyncio
    async def test_cached_response_with_cost_calculator(self):
        """Test caching with cost calculation"""
        _global_cache.clear()
        messages = [{"role": "user", "content": "Test"}]
        
        def cost_calc(model, prompt_tokens, completion_tokens):
            return 0.05
        
        @cached_response("openai", "gpt-4", cost_calculator=cost_calc)
        async def mock_generate(**kwargs):
            response = MagicMock()
            response.usage = {"prompt_tokens": 100, "completion_tokens": 50}
            return response
        
        result = await mock_generate(messages=messages, temperature=0.7)
        
        # Check that cost was calculated and stored
        key = CacheKey.from_request("openai", "gpt-4", messages, 0.7)
        cached = _global_cache.cache[key.to_string()]
        assert cached.cost_saved == 0.05
    
    def test_global_cache_instance(self):
        """Test that global cache instance works correctly"""
        assert isinstance(_global_cache, ResponseCache)
        
        # Test that it can be used
        key = CacheKey("test", "model", "hash", 0.5)
        _global_cache.set(key, {"test": "data"})
        
        result = _global_cache.get(key)
        assert result == {"test": "data"}