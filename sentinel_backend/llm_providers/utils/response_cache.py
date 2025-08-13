"""Response caching for LLM providers to reduce costs and latency."""

import hashlib
import json
import logging
import pickle
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class CacheKey:
    """Cache key for LLM responses."""
    provider: str
    model: str
    messages_hash: str
    temperature: float
    max_tokens: Optional[int] = None
    tools_hash: Optional[str] = None
    
    def to_string(self) -> str:
        """Convert to string key for cache storage."""
        parts = [
            self.provider,
            self.model,
            self.messages_hash,
            str(self.temperature),
            str(self.max_tokens or "none"),
            self.tools_hash or "none"
        ]
        return ":".join(parts)
    
    @classmethod
    def from_request(
        cls,
        provider: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None
    ) -> "CacheKey":
        """Create cache key from request parameters."""
        # Hash messages
        messages_str = json.dumps(messages, sort_keys=True)
        messages_hash = hashlib.sha256(messages_str.encode()).hexdigest()[:16]
        
        # Hash tools if provided
        tools_hash = None
        if tools:
            tools_str = json.dumps(tools, sort_keys=True)
            tools_hash = hashlib.sha256(tools_str.encode()).hexdigest()[:16]
        
        return cls(
            provider=provider,
            model=model,
            messages_hash=messages_hash,
            temperature=temperature,
            max_tokens=max_tokens,
            tools_hash=tools_hash
        )


@dataclass
class CachedResponse:
    """Cached LLM response with metadata."""
    response: Any
    timestamp: datetime
    hit_count: int = 0
    cost_saved: float = 0.0
    time_saved: float = 0.0
    
    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if cache entry is expired."""
        age = datetime.now() - self.timestamp
        return age.total_seconds() > ttl_seconds


class ResponseCache:
    """LLM response cache with TTL and size limits."""
    
    def __init__(
        self,
        max_size: int = 1000,
        ttl_seconds: int = 3600,
        enabled: bool = True
    ):
        """
        Initialize response cache.
        
        Args:
            max_size: Maximum number of cached responses
            ttl_seconds: Time-to-live for cache entries
            enabled: Whether caching is enabled
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        self.cache: Dict[str, CachedResponse] = {}
        self.stats = {
            "hits": 0,
            "misses": 0,
            "total_cost_saved": 0.0,
            "total_time_saved": 0.0,
            "evictions": 0
        }
    
    def get(self, key: CacheKey) -> Optional[Any]:
        """
        Get cached response if available.
        
        Args:
            key: Cache key
            
        Returns:
            Cached response or None
        """
        if not self.enabled:
            return None
        
        key_str = key.to_string()
        
        if key_str in self.cache:
            cached = self.cache[key_str]
            
            # Check expiration
            if cached.is_expired(self.ttl_seconds):
                del self.cache[key_str]
                self.stats["misses"] += 1
                return None
            
            # Update stats
            cached.hit_count += 1
            self.stats["hits"] += 1
            
            logger.debug(f"Cache hit for key: {key_str[:50]}...")
            return cached.response
        
        self.stats["misses"] += 1
        return None
    
    def set(
        self,
        key: CacheKey,
        response: Any,
        cost: float = 0.0,
        elapsed_time: float = 0.0
    ):
        """
        Store response in cache.
        
        Args:
            key: Cache key
            response: Response to cache
            cost: Cost of the API call
            elapsed_time: Time taken for the API call
        """
        if not self.enabled:
            return
        
        # Check cache size and evict if necessary
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        
        key_str = key.to_string()
        
        # Store in cache
        self.cache[key_str] = CachedResponse(
            response=response,
            timestamp=datetime.now(),
            cost_saved=cost,
            time_saved=elapsed_time
        )
        
        logger.debug(f"Cached response for key: {key_str[:50]}...")
    
    def _evict_oldest(self):
        """Evict oldest cache entry."""
        if not self.cache:
            return
        
        # Find oldest entry
        oldest_key = min(
            self.cache.keys(),
            key=lambda k: self.cache[k].timestamp
        )
        
        # Update stats before eviction
        evicted = self.cache[oldest_key]
        self.stats["total_cost_saved"] += evicted.cost_saved * evicted.hit_count
        self.stats["total_time_saved"] += evicted.time_saved * evicted.hit_count
        self.stats["evictions"] += 1
        
        # Remove from cache
        del self.cache[oldest_key]
        logger.debug(f"Evicted cache entry: {oldest_key[:50]}...")
    
    def clear(self):
        """Clear all cached responses."""
        # Update stats before clearing
        for cached in self.cache.values():
            self.stats["total_cost_saved"] += cached.cost_saved * cached.hit_count
            self.stats["total_time_saved"] += cached.time_saved * cached.hit_count
        
        self.cache.clear()
        logger.info("Cache cleared")
    
    def cleanup_expired(self):
        """Remove expired entries from cache."""
        expired_keys = [
            key for key, cached in self.cache.items()
            if cached.is_expired(self.ttl_seconds)
        ]
        
        for key in expired_keys:
            cached = self.cache[key]
            self.stats["total_cost_saved"] += cached.cost_saved * cached.hit_count
            self.stats["total_time_saved"] += cached.time_saved * cached.hit_count
            del self.cache[key]
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "enabled": self.enabled,
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": f"{hit_rate:.2f}%",
            "evictions": self.stats["evictions"],
            "cost_saved": f"${self.stats['total_cost_saved']:.4f}",
            "time_saved": f"{self.stats['total_time_saved']:.2f}s"
        }
    
    def save_to_disk(self, filepath: str):
        """Save cache to disk for persistence."""
        try:
            with open(filepath, "wb") as f:
                pickle.dump({
                    "cache": self.cache,
                    "stats": self.stats
                }, f)
            logger.info(f"Cache saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def load_from_disk(self, filepath: str):
        """Load cache from disk."""
        try:
            with open(filepath, "rb") as f:
                data = pickle.load(f)
                self.cache = data["cache"]
                self.stats = data["stats"]
            
            # Cleanup expired entries
            self.cleanup_expired()
            logger.info(f"Cache loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")


# Global cache instance
_global_cache = ResponseCache()


def cached_response(
    provider: str,
    model: str,
    cost_calculator=None
):
    """
    Decorator for caching LLM responses.
    
    Args:
        provider: Provider name
        model: Model name
        cost_calculator: Optional function to calculate cost
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract parameters for cache key
            messages = kwargs.get("messages", [])
            temperature = kwargs.get("temperature", 0.7)
            max_tokens = kwargs.get("max_tokens")
            tools = kwargs.get("tools")
            
            # Create cache key
            cache_key = CacheKey.from_request(
                provider=provider,
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools
            )
            
            # Check cache
            cached = _global_cache.get(cache_key)
            if cached is not None:
                logger.info(f"Using cached response for {provider}/{model}")
                return cached
            
            # Call original function
            start_time = time.time()
            response = await func(*args, **kwargs)
            elapsed_time = time.time() - start_time
            
            # Calculate cost if possible
            cost = 0.0
            if cost_calculator and hasattr(response, "usage"):
                cost = cost_calculator(
                    model,
                    response.usage.get("prompt_tokens", 0),
                    response.usage.get("completion_tokens", 0)
                )
            
            # Store in cache
            _global_cache.set(cache_key, response, cost, elapsed_time)
            
            return response
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Extract parameters for cache key
            messages = kwargs.get("messages", [])
            temperature = kwargs.get("temperature", 0.7)
            max_tokens = kwargs.get("max_tokens")
            tools = kwargs.get("tools")
            
            # Create cache key
            cache_key = CacheKey.from_request(
                provider=provider,
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools
            )
            
            # Check cache
            cached = _global_cache.get(cache_key)
            if cached is not None:
                logger.info(f"Using cached response for {provider}/{model}")
                return cached
            
            # Call original function
            start_time = time.time()
            response = func(*args, **kwargs)
            elapsed_time = time.time() - start_time
            
            # Calculate cost if possible
            cost = 0.0
            if cost_calculator and hasattr(response, "usage"):
                cost = cost_calculator(
                    model,
                    response.usage.get("prompt_tokens", 0),
                    response.usage.get("completion_tokens", 0)
                )
            
            # Store in cache
            _global_cache.set(cache_key, response, cost, elapsed_time)
            
            return response
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator