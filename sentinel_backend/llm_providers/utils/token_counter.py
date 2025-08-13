"""Token counting utilities for different LLM providers."""

import logging
from typing import List, Dict, Any, Optional, Union
import tiktoken
import json

logger = logging.getLogger(__name__)


class TokenCounter:
    """Unified token counter for multiple LLM providers."""
    
    # Token approximation ratios (tokens per character) for different languages
    CHAR_TO_TOKEN_RATIOS = {
        "english": 0.25,  # ~4 chars per token
        "code": 0.3,      # Code is more dense
        "chinese": 0.5,   # Chinese characters are more token-heavy
        "default": 0.25
    }
    
    # Model-specific encodings for OpenAI
    OPENAI_ENCODINGS = {
        "gpt-4": "cl100k_base",
        "gpt-4-turbo": "cl100k_base",
        "gpt-4-turbo-preview": "cl100k_base",
        "gpt-3.5-turbo": "cl100k_base",
        "text-davinci-003": "p50k_base",
        "text-davinci-002": "p50k_base",
    }
    
    def __init__(self):
        """Initialize token counter with encoding caches."""
        self._encodings = {}
        self._load_tiktoken_encodings()
    
    def _load_tiktoken_encodings(self):
        """Pre-load tiktoken encodings for OpenAI models."""
        try:
            for model, encoding_name in self.OPENAI_ENCODINGS.items():
                self._encodings[model] = tiktoken.get_encoding(encoding_name)
        except Exception as e:
            logger.warning(f"Failed to load tiktoken encodings: {e}")
    
    def count_tokens(
        self,
        text: Union[str, List[Dict[str, str]]],
        model: str,
        provider: Optional[str] = None
    ) -> int:
        """
        Count tokens for text or messages.
        
        Args:
            text: String or list of message dicts
            model: Model name
            provider: Provider name (optional, will try to infer)
            
        Returns:
            Token count
        """
        # Convert messages to text if needed
        if isinstance(text, list):
            text = self._messages_to_text(text)
        
        # Determine provider if not specified
        if not provider:
            provider = self._infer_provider(model)
        
        # Use provider-specific counting
        if provider == "openai":
            return self._count_openai_tokens(text, model)
        elif provider == "anthropic":
            return self._count_anthropic_tokens(text, model)
        elif provider == "google":
            return self._count_google_tokens(text, model)
        else:
            return self._estimate_tokens(text)
    
    def _messages_to_text(self, messages: List[Dict[str, str]]) -> str:
        """Convert messages to a single text string."""
        parts = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            parts.append(f"{role}: {content}")
        return "\n".join(parts)
    
    def _infer_provider(self, model: str) -> str:
        """Infer provider from model name."""
        model_lower = model.lower()
        
        if "gpt" in model_lower or "davinci" in model_lower:
            return "openai"
        elif "claude" in model_lower:
            return "anthropic"
        elif "gemini" in model_lower:
            return "google"
        elif "mistral" in model_lower or "mixtral" in model_lower:
            return "mistral"
        elif "llama" in model_lower or "deepseek" in model_lower or "qwen" in model_lower:
            return "ollama"
        else:
            return "unknown"
    
    def _count_openai_tokens(self, text: str, model: str) -> int:
        """Count tokens for OpenAI models using tiktoken."""
        try:
            # Find the right encoding for the model
            encoding = None
            for model_prefix, enc in self._encodings.items():
                if model.startswith(model_prefix):
                    encoding = enc
                    break
            
            if not encoding:
                # Try to get encoding by model name
                encoding = tiktoken.encoding_for_model(model)
            
            if encoding:
                tokens = encoding.encode(text)
                return len(tokens)
        except Exception as e:
            logger.debug(f"Failed to use tiktoken for {model}: {e}")
        
        # Fallback to estimation
        return self._estimate_tokens(text)
    
    def _count_anthropic_tokens(self, text: str, model: str) -> int:
        """Count tokens for Anthropic models."""
        # Anthropic uses a similar tokenization to OpenAI's cl100k_base
        # but with some differences. We'll use an approximation.
        
        try:
            # Try using cl100k_base as approximation
            if "cl100k_base" in self._encodings:
                encoding = self._encodings["cl100k_base"]
            else:
                encoding = tiktoken.get_encoding("cl100k_base")
            
            tokens = encoding.encode(text)
            # Anthropic tokens are slightly different, add 5% margin
            return int(len(tokens) * 1.05)
        except Exception:
            pass
        
        # Fallback: Anthropic averages ~3.5 characters per token
        return len(text) // 3.5
    
    def _count_google_tokens(self, text: str, model: str) -> int:
        """Count tokens for Google Gemini models."""
        # Gemini uses SentencePiece tokenization
        # Approximation: ~4 characters per token for English
        
        # Check if text contains code
        if "```" in text or "def " in text or "function " in text:
            ratio = self.CHAR_TO_TOKEN_RATIOS["code"]
        else:
            ratio = self.CHAR_TO_TOKEN_RATIOS["english"]
        
        return int(len(text) * ratio)
    
    def _estimate_tokens(self, text: str, language: str = "default") -> int:
        """Estimate token count based on character count."""
        ratio = self.CHAR_TO_TOKEN_RATIOS.get(language, self.CHAR_TO_TOKEN_RATIOS["default"])
        return int(len(text) * ratio)
    
    def count_messages_tokens(
        self,
        messages: List[Dict[str, str]],
        model: str,
        provider: Optional[str] = None
    ) -> int:
        """
        Count tokens for a list of messages with role formatting.
        
        Args:
            messages: List of message dictionaries
            model: Model name
            provider: Provider name
            
        Returns:
            Total token count including formatting
        """
        if not provider:
            provider = self._infer_provider(model)
        
        total_tokens = 0
        
        # Different providers have different message formatting overhead
        if provider == "openai":
            # OpenAI adds ~4 tokens per message for formatting
            for message in messages:
                total_tokens += 4  # Message formatting overhead
                total_tokens += self.count_tokens(message.get("content", ""), model, provider)
                
                # Function calls have additional overhead
                if "function_call" in message:
                    total_tokens += self.count_tokens(
                        json.dumps(message["function_call"]), model, provider
                    )
            
            # Add 2 tokens for priming
            total_tokens += 2
            
        elif provider == "anthropic":
            # Anthropic has different formatting
            for message in messages:
                role = message.get("role", "")
                content = message.get("content", "")
                
                # Anthropic adds "Human: " or "Assistant: " prefixes
                if role == "user":
                    total_tokens += self.count_tokens(f"Human: {content}", model, provider)
                elif role == "assistant":
                    total_tokens += self.count_tokens(f"Assistant: {content}", model, provider)
                else:
                    total_tokens += self.count_tokens(content, model, provider)
            
        else:
            # Generic counting
            for message in messages:
                total_tokens += self.count_tokens(message.get("content", ""), model, provider)
                total_tokens += 2  # Small overhead for role
        
        return total_tokens
    
    def fits_in_context(
        self,
        text: Union[str, List[Dict[str, str]]],
        model: str,
        max_context: int,
        response_buffer: int = 1000
    ) -> bool:
        """
        Check if text fits in model's context window.
        
        Args:
            text: Text or messages to check
            model: Model name
            max_context: Maximum context window size
            response_buffer: Tokens to reserve for response
            
        Returns:
            True if text fits with buffer
        """
        token_count = self.count_tokens(text, model)
        return (token_count + response_buffer) <= max_context
    
    def truncate_to_fit(
        self,
        text: str,
        model: str,
        max_tokens: int,
        provider: Optional[str] = None
    ) -> str:
        """
        Truncate text to fit within token limit.
        
        Args:
            text: Text to truncate
            model: Model name
            max_tokens: Maximum token count
            provider: Provider name
            
        Returns:
            Truncated text
        """
        current_tokens = self.count_tokens(text, model, provider)
        
        if current_tokens <= max_tokens:
            return text
        
        # Binary search for the right truncation point
        left, right = 0, len(text)
        result = ""
        
        while left < right:
            mid = (left + right + 1) // 2
            truncated = text[:mid]
            tokens = self.count_tokens(truncated, model, provider)
            
            if tokens <= max_tokens:
                result = truncated
                left = mid
            else:
                right = mid - 1
        
        return result + "..." if result else text[:100] + "..."


# Convenience functions
_default_counter = TokenCounter()

def estimate_tokens(text: str, language: str = "default") -> int:
    """Quick token estimation based on character count."""
    return _default_counter._estimate_tokens(text, language)

def count_tokens_for_model(
    text: Union[str, List[Dict[str, str]]],
    model: str,
    provider: Optional[str] = None
) -> int:
    """Count tokens for specific model."""
    return _default_counter.count_tokens(text, model, provider)