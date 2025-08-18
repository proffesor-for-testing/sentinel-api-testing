"""
Comprehensive Unit Tests for Token Counter

This module provides extensive test coverage for token counting utilities,
including model-specific counting, estimation, and truncation.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

from sentinel_backend.llm_providers.utils.token_counter import (
    TokenCounter, estimate_tokens, count_tokens_for_model
)


class TestTokenCounter:
    """Test suite for TokenCounter class"""
    
    @pytest.fixture
    def counter(self):
        """Create a TokenCounter instance"""
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken'):
            return TokenCounter()
    
    def test_initialization(self):
        """Test TokenCounter initialization"""
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken') as mock_tiktoken:
            mock_encoding = MagicMock()
            mock_tiktoken.get_encoding.return_value = mock_encoding
            
            counter = TokenCounter()
            
            # Should load OpenAI encodings
            assert mock_tiktoken.get_encoding.called
            assert len(counter._encodings) > 0
    
    def test_initialization_error_handling(self):
        """Test handling of tiktoken loading errors"""
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken.get_encoding') as mock_get:
            mock_get.side_effect = Exception("Failed to load")
            
            with patch('sentinel_backend.llm_providers.utils.token_counter.logger') as mock_logger:
                counter = TokenCounter()
                mock_logger.warning.assert_called_once()
    
    def test_count_tokens_string_input(self, counter):
        """Test counting tokens for string input"""
        text = "This is a test string for token counting."
        
        # Test with OpenAI model
        with patch.object(counter, '_count_openai_tokens', return_value=10):
            count = counter.count_tokens(text, "gpt-4", "openai")
            assert count == 10
        
        # Test with Anthropic model
        with patch.object(counter, '_count_anthropic_tokens', return_value=12):
            count = counter.count_tokens(text, "claude-3", "anthropic")
            assert count == 12
    
    def test_count_tokens_messages_input(self, counter):
        """Test counting tokens for message list input"""
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ]
        
        with patch.object(counter, '_count_openai_tokens', return_value=20):
            count = counter.count_tokens(messages, "gpt-4", "openai")
            assert count == 20
    
    def test_messages_to_text_conversion(self, counter):
        """Test converting messages to text"""
        messages = [
            {"role": "system", "content": "System message"},
            {"role": "user", "content": "User message"},
            {"role": "assistant", "content": "Assistant message"}
        ]
        
        text = counter._messages_to_text(messages)
        
        assert "system: System message" in text
        assert "user: User message" in text
        assert "assistant: Assistant message" in text
    
    def test_infer_provider(self, counter):
        """Test provider inference from model name"""
        test_cases = [
            ("gpt-4", "openai"),
            ("gpt-3.5-turbo", "openai"),
            ("text-davinci-003", "openai"),
            ("claude-3-opus", "anthropic"),
            ("claude-sonnet", "anthropic"),
            ("gemini-pro", "google"),
            ("gemini-1.5", "google"),
            ("mistral-7b", "mistral"),
            ("mixtral-8x7b", "mistral"),
            ("llama-3", "ollama"),
            ("deepseek-coder", "ollama"),
            ("qwen-72b", "ollama"),
            ("unknown-model", "unknown")
        ]
        
        for model, expected_provider in test_cases:
            provider = counter._infer_provider(model)
            assert provider == expected_provider
    
    def test_count_openai_tokens(self, counter):
        """Test OpenAI-specific token counting"""
        text = "This is a test text for OpenAI token counting."
        
        # Mock tiktoken encoding
        mock_encoding = MagicMock()
        mock_encoding.encode.return_value = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        counter._encodings["gpt-4"] = mock_encoding
        
        count = counter._count_openai_tokens(text, "gpt-4")
        assert count == 10
        mock_encoding.encode.assert_called_once_with(text)
    
    def test_count_openai_tokens_with_encoding_for_model(self, counter):
        """Test OpenAI token counting with encoding_for_model"""
        text = "Test text"
        
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken.encoding_for_model') as mock_enc:
            mock_encoding = MagicMock()
            mock_encoding.encode.return_value = [1, 2, 3, 4, 5]
            mock_enc.return_value = mock_encoding
            
            # Model not in encodings dict
            counter._encodings = {}
            count = counter._count_openai_tokens(text, "gpt-4-custom")
            
            assert count == 5
            mock_enc.assert_called_once_with("gpt-4-custom")
    
    def test_count_openai_tokens_fallback(self, counter):
        """Test OpenAI token counting fallback to estimation"""
        text = "Test text for fallback"
        
        # No encodings available
        counter._encodings = {}
        
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken.encoding_for_model') as mock_enc:
            mock_enc.side_effect = Exception("No encoding")
            
            with patch.object(counter, '_estimate_tokens', return_value=10):
                count = counter._count_openai_tokens(text, "unknown-model")
                assert count == 10
    
    def test_count_anthropic_tokens(self, counter):
        """Test Anthropic-specific token counting"""
        text = "Test text for Anthropic"
        
        # Should use cl100k_base encoding with 5% margin
        mock_encoding = MagicMock()
        mock_encoding.encode.return_value = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        counter._encodings["cl100k_base"] = mock_encoding
        
        count = counter._count_anthropic_tokens(text, "claude-3")
        
        # Should be 10 * 1.05 = 10.5, rounded to 10
        assert count == 10
    
    def test_count_anthropic_tokens_fallback(self, counter):
        """Test Anthropic token counting fallback"""
        text = "A" * 35  # 35 characters
        
        # No cl100k_base encoding
        counter._encodings = {}
        
        with patch('sentinel_backend.llm_providers.utils.token_counter.tiktoken.get_encoding') as mock_get:
            mock_get.side_effect = Exception("No encoding")
            
            count = counter._count_anthropic_tokens(text, "claude-3")
            
            # Fallback: 35 chars / 3.5 = 10
            assert count == 10
    
    def test_count_google_tokens(self, counter):
        """Test Google Gemini token counting"""
        # Regular text
        text = "This is regular text"
        count = counter._count_google_tokens(text, "gemini-pro")
        
        # Should use default English ratio (0.25)
        expected = int(len(text) * 0.25)
        assert count == expected
        
        # Code text
        code_text = "```python\ndef hello():\n    print('world')\n```"
        count = counter._count_google_tokens(code_text, "gemini-pro")
        
        # Should detect code and use code ratio (0.3)
        expected = int(len(code_text) * 0.3)
        assert count == expected
    
    def test_estimate_tokens(self, counter):
        """Test generic token estimation"""
        text = "A" * 100  # 100 characters
        
        # Default language
        count = counter._estimate_tokens(text)
        assert count == 25  # 100 * 0.25
        
        # English
        count = counter._estimate_tokens(text, "english")
        assert count == 25
        
        # Code
        count = counter._estimate_tokens(text, "code")
        assert count == 30  # 100 * 0.3
        
        # Chinese
        count = counter._estimate_tokens(text, "chinese")
        assert count == 50  # 100 * 0.5
        
        # Unknown language
        count = counter._estimate_tokens(text, "unknown")
        assert count == 25  # Falls back to default
    
    def test_count_messages_tokens(self, counter):
        """Test counting tokens for message lists with formatting"""
        messages = [
            {"role": "system", "content": "System prompt"},
            {"role": "user", "content": "User message"},
            {"role": "assistant", "content": "Assistant response"}
        ]
        
        # Test OpenAI formatting
        with patch.object(counter, 'count_tokens', side_effect=[10, 8, 12]):
            total = counter.count_messages_tokens(messages, "gpt-4", "openai")
            
            # 3 messages * 4 tokens overhead + content tokens + 2 priming
            # 12 + 10 + 8 + 12 + 2 = 44
            assert total == 44
    
    def test_count_messages_tokens_with_function_call(self, counter):
        """Test counting tokens for messages with function calls"""
        messages = [
            {"role": "user", "content": "Call a function"},
            {
                "role": "assistant",
                "content": "",
                "function_call": {"name": "test_func", "arguments": '{"arg": "value"}'}
            }
        ]
        
        with patch.object(counter, 'count_tokens', side_effect=[10, 0, 15]):
            total = counter.count_messages_tokens(messages, "gpt-4", "openai")
            
            # Should include function call tokens
            assert total > 0
    
    def test_count_messages_tokens_anthropic(self, counter):
        """Test Anthropic message formatting"""
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"}
        ]
        
        with patch.object(counter, 'count_tokens', side_effect=[15, 20]):
            total = counter.count_messages_tokens(messages, "claude-3", "anthropic")
            
            # Should format as "Human: Hello" and "Assistant: Hi there"
            assert total == 35
    
    def test_count_messages_tokens_generic(self, counter):
        """Test generic message token counting"""
        messages = [
            {"role": "user", "content": "Message 1"},
            {"role": "assistant", "content": "Message 2"}
        ]
        
        with patch.object(counter, 'count_tokens', side_effect=[10, 12]):
            total = counter.count_messages_tokens(messages, "unknown-model", "unknown")
            
            # Generic: content tokens + 2 overhead per message
            assert total == 26  # 10 + 2 + 12 + 2
    
    def test_fits_in_context(self, counter):
        """Test checking if text fits in context window"""
        text = "Test text"
        
        with patch.object(counter, 'count_tokens', return_value=500):
            # Should fit
            fits = counter.fits_in_context(text, "gpt-4", 2000, response_buffer=1000)
            assert fits is True
            
            # Should not fit (500 + 1000 > 1400)
            fits = counter.fits_in_context(text, "gpt-4", 1400, response_buffer=1000)
            assert fits is False
    
    def test_truncate_to_fit(self, counter):
        """Test truncating text to fit token limit"""
        text = "This is a long text that needs to be truncated to fit within the token limit."
        
        # Mock count_tokens to return decreasing values as text is truncated
        token_counts = [100, 80, 60, 40, 20, 10, 5, 3, 2, 1]
        with patch.object(counter, 'count_tokens', side_effect=token_counts):
            truncated = counter.truncate_to_fit(text, "gpt-4", 30)
            
            # Should be truncated
            assert len(truncated) < len(text)
            assert truncated.endswith("...")
    
    def test_truncate_to_fit_no_truncation_needed(self, counter):
        """Test that text is not truncated if it fits"""
        text = "Short text"
        
        with patch.object(counter, 'count_tokens', return_value=10):
            truncated = counter.truncate_to_fit(text, "gpt-4", 20)
            
            assert truncated == text
    
    def test_truncate_to_fit_binary_search(self, counter):
        """Test binary search algorithm in truncation"""
        text = "A" * 1000
        
        # Simulate token counts for binary search
        def mock_count(t, model, provider):
            return len(t) // 4  # Simple estimation
        
        with patch.object(counter, 'count_tokens', side_effect=mock_count):
            truncated = counter.truncate_to_fit(text, "gpt-4", 100)
            
            # Should be around 400 characters (100 * 4)
            assert len(truncated) < 450
            assert truncated.endswith("...")


class TestGlobalFunctions:
    """Test suite for global convenience functions"""
    
    def test_estimate_tokens_global(self):
        """Test global estimate_tokens function"""
        text = "A" * 100
        
        # Default language
        tokens = estimate_tokens(text)
        assert tokens == 25
        
        # Specific language
        tokens = estimate_tokens(text, "code")
        assert tokens == 30
    
    def test_count_tokens_for_model_global(self):
        """Test global count_tokens_for_model function"""
        with patch('sentinel_backend.llm_providers.utils.token_counter._default_counter') as mock_counter:
            mock_counter.count_tokens.return_value = 50
            count = count_tokens_for_model("Test text", "gpt-4", "openai")
            assert count == 50
    
    def test_openai_encoding_mappings(self):
        """Test OpenAI model encoding mappings"""
        counter = TokenCounter()
        
        expected_mappings = {
            "gpt-4": "cl100k_base",
            "gpt-4-turbo": "cl100k_base",
            "gpt-3.5-turbo": "cl100k_base",
            "text-davinci-003": "p50k_base",
            "text-davinci-002": "p50k_base",
        }
        
        for model, encoding in expected_mappings.items():
            assert counter.OPENAI_ENCODINGS[model] == encoding
    
    def test_char_to_token_ratios(self):
        """Test character to token ratio constants"""
        counter = TokenCounter()
        
        assert counter.CHAR_TO_TOKEN_RATIOS["english"] == 0.25
        assert counter.CHAR_TO_TOKEN_RATIOS["code"] == 0.3
        assert counter.CHAR_TO_TOKEN_RATIOS["chinese"] == 0.5
        assert counter.CHAR_TO_TOKEN_RATIOS["default"] == 0.25