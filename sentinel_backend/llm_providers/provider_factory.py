"""
LLM Provider Factory

Factory pattern implementation for creating LLM provider instances.
Handles provider selection, fallback mechanisms, and configuration.
"""

from typing import Optional, List, Dict, Any
import structlog
from .base_provider import BaseLLMProvider, LLMProvider, LLMConfig
from .model_registry import get_model_spec, MODEL_REGISTRY

logger = structlog.get_logger(__name__)


class LLMProviderFactory:
    """
    Factory for creating LLM provider instances.
    
    Supports:
    - Dynamic provider instantiation
    - Automatic fallback to secondary providers
    - Configuration validation
    - Provider health checks
    """
    
    _providers: Dict[str, type] = {}
    _instances: Dict[str, BaseLLMProvider] = {}
    
    @classmethod
    def register_provider(cls, provider_type: LLMProvider, provider_class: type):
        """
        Register a provider implementation.
        
        Args:
            provider_type: The provider type enum
            provider_class: The provider implementation class
        """
        cls._providers[provider_type.value] = provider_class
        logger.info(f"Registered LLM provider: {provider_type.value}")
    
    @classmethod
    def create_provider(
        cls,
        config: LLMConfig,
        use_cache: bool = True
    ) -> BaseLLMProvider:
        """
        Create or retrieve a provider instance.
        
        Args:
            config: LLM configuration
            use_cache: Whether to use cached instances
            
        Returns:
            Provider instance
            
        Raises:
            ValueError: If provider is not supported
        """
        cache_key = f"{config.provider.value}:{config.model}"
        
        # Return cached instance if available
        if use_cache and cache_key in cls._instances:
            logger.debug(f"Using cached provider instance: {cache_key}")
            return cls._instances[cache_key]
        
        # Validate provider is registered
        if config.provider.value not in cls._providers:
            # Try to auto-import the provider
            cls._auto_import_provider(config.provider)
            
            if config.provider.value not in cls._providers:
                raise ValueError(
                    f"Provider '{config.provider.value}' not supported. "
                    f"Available providers: {list(cls._providers.keys())}"
                )
        
        # Validate model is supported
        model_key = cls._find_model_key(config.model)
        if not model_key:
            logger.warning(
                f"Model '{config.model}' not found in registry. "
                "Proceeding without model validation."
            )
        else:
            model_spec = MODEL_REGISTRY[model_key]
            if model_spec.provider != config.provider:
                logger.warning(
                    f"Model '{config.model}' is registered for provider "
                    f"'{model_spec.provider.value}' but being used with "
                    f"'{config.provider.value}'"
                )
        
        # Create provider instance
        provider_class = cls._providers[config.provider.value]
        instance = provider_class(config)
        
        # Cache the instance
        if use_cache:
            cls._instances[cache_key] = instance
            logger.info(f"Created and cached provider: {cache_key}")
        
        return instance
    
    @classmethod
    def create_with_fallback(
        cls,
        primary_config: LLMConfig,
        fallback_configs: Optional[List[LLMConfig]] = None,
        app_settings: Optional[Any] = None
    ) -> 'FallbackLLMProvider':
        """
        Create a provider with automatic fallback support.
        
        Args:
            primary_config: Primary provider configuration
            fallback_configs: List of fallback configurations
            app_settings: Application settings for default fallbacks
            
        Returns:
            Provider with fallback support
        """
        providers = []
        configs = [primary_config]
        
        # Add fallback configurations
        if fallback_configs:
            configs.extend(fallback_configs)
        elif app_settings and app_settings.llm_fallback_enabled:
            # Create fallback configs from settings
            for provider_name in app_settings.llm_fallback_providers:
                if provider_name == primary_config.provider.value:
                    continue  # Skip primary provider
                
                fallback_model = app_settings.llm_fallback_models.get(
                    provider_name,
                    "gpt-3.5-turbo"  # Default fallback
                )
                
                fallback_config = LLMConfig(
                    provider=LLMProvider(provider_name),
                    model=fallback_model,
                    api_key=cls._get_api_key_for_provider(provider_name, app_settings),
                    temperature=primary_config.temperature,
                    max_tokens=primary_config.max_tokens,
                    timeout=primary_config.timeout
                )
                configs.append(fallback_config)
        
        # Create provider instances
        for config in configs:
            try:
                provider = cls.create_provider(config)
                providers.append(provider)
            except Exception as e:
                logger.warning(
                    f"Failed to create provider {config.provider.value}: {e}"
                )
        
        if not providers:
            raise ValueError("No valid providers could be created")
        
        return FallbackLLMProvider(providers)
    
    @classmethod
    def _auto_import_provider(cls, provider_type: LLMProvider):
        """
        Attempt to auto-import a provider module.
        
        Args:
            provider_type: Provider type to import
        """
        try:
            if provider_type == LLMProvider.OPENAI:
                from .providers.openai_provider import OpenAIProvider
                cls.register_provider(LLMProvider.OPENAI, OpenAIProvider)
            elif provider_type == LLMProvider.ANTHROPIC:
                from .providers.anthropic_provider import AnthropicProvider
                cls.register_provider(LLMProvider.ANTHROPIC, AnthropicProvider)
            elif provider_type == LLMProvider.GOOGLE:
                from .providers.google_provider import GoogleProvider
                cls.register_provider(LLMProvider.GOOGLE, GoogleProvider)
            elif provider_type == LLMProvider.MISTRAL:
                from .providers.mistral_provider import MistralProvider
                cls.register_provider(LLMProvider.MISTRAL, MistralProvider)
            elif provider_type == LLMProvider.OLLAMA:
                from .providers.ollama_provider import OllamaProvider
                cls.register_provider(LLMProvider.OLLAMA, OllamaProvider)
            elif provider_type == LLMProvider.VLLM:
                from .providers.vllm_provider import VLLMProvider
                cls.register_provider(LLMProvider.VLLM, VLLMProvider)
            elif provider_type == LLMProvider.MOCK:
                from .mock_provider import MockLLMProvider
                cls.register_provider(LLMProvider.MOCK, MockLLMProvider)
        except ImportError as e:
            logger.debug(f"Could not auto-import provider {provider_type.value}: {e}")
    
    @classmethod
    def _find_model_key(cls, model_name: str) -> Optional[str]:
        """
        Find a model key in the registry by name.
        
        Args:
            model_name: Model name to search for
            
        Returns:
            Model key if found, None otherwise
        """
        # Direct match
        if model_name in MODEL_REGISTRY:
            return model_name
        
        # Search by model_id
        for key, spec in MODEL_REGISTRY.items():
            if spec.model_id == model_name:
                return key
        
        # Partial match (for flexibility)
        for key, spec in MODEL_REGISTRY.items():
            if model_name in spec.model_id or model_name in key:
                return key
        
        return None
    
    @classmethod
    def _get_api_key_for_provider(
        cls,
        provider_name: str,
        app_settings: Any
    ) -> Optional[str]:
        """
        Get API key for a provider from settings.
        
        Args:
            provider_name: Provider name
            app_settings: Application settings
            
        Returns:
            API key if available
        """
        key_mapping = {
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "google": "google_api_key",
            "mistral": "mistral_api_key"
        }
        
        attr_name = key_mapping.get(provider_name)
        if attr_name:
            return getattr(app_settings, attr_name, None)
        
        return None
    
    @classmethod
    def list_available_providers(cls) -> List[str]:
        """Get list of available providers."""
        return list(cls._providers.keys())
    
    @classmethod
    def clear_cache(cls):
        """Clear the provider instance cache."""
        cls._instances.clear()
        logger.info("Cleared provider instance cache")


class FallbackLLMProvider(BaseLLMProvider):
    """
    Provider wrapper that implements automatic fallback.
    
    Tries each provider in sequence until one succeeds.
    """
    
    def __init__(self, providers: List[BaseLLMProvider]):
        """
        Initialize with a list of providers.
        
        Args:
            providers: List of providers to use (in order)
        """
        if not providers:
            raise ValueError("At least one provider required")
        
        self.providers = providers
        self.primary_provider = providers[0]
        self.config = self.primary_provider.config
        
        logger.info(
            f"Initialized fallback provider with {len(providers)} providers"
        )
    
    def _validate_config(self) -> None:
        """Validation handled by individual providers."""
        pass
    
    async def generate(self, messages, **kwargs):
        """
        Generate with automatic fallback.
        
        Try each provider until one succeeds.
        """
        last_error = None
        
        for i, provider in enumerate(self.providers):
            try:
                logger.debug(f"Attempting generation with provider {i+1}/{len(self.providers)}")
                response = await provider.generate(messages, **kwargs)
                
                if i > 0:  # Used fallback
                    logger.info(
                        f"Successfully used fallback provider: "
                        f"{provider.config.provider.value}"
                    )
                
                return response
                
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Provider {provider.config.provider.value} failed: {e}"
                )
                
                if i < len(self.providers) - 1:
                    logger.info(f"Trying fallback provider {i+2}...")
        
        # All providers failed
        raise RuntimeError(
            f"All {len(self.providers)} providers failed. Last error: {last_error}"
        )
    
    async def stream_generate(self, messages, **kwargs):
        """Stream with automatic fallback."""
        last_error = None
        
        for i, provider in enumerate(self.providers):
            try:
                logger.debug(f"Attempting streaming with provider {i+1}/{len(self.providers)}")
                
                async for chunk in provider.stream_generate(messages, **kwargs):
                    yield chunk
                
                if i > 0:
                    logger.info(
                        f"Successfully used fallback provider for streaming: "
                        f"{provider.config.provider.value}"
                    )
                return
                
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Provider {provider.config.provider.value} failed streaming: {e}"
                )
                
                if i < len(self.providers) - 1:
                    logger.info(f"Trying fallback provider {i+2} for streaming...")
        
        raise RuntimeError(
            f"All {len(self.providers)} providers failed streaming. Last error: {last_error}"
        )
    
    def get_capabilities(self):
        """Get capabilities of the primary provider."""
        return self.primary_provider.get_capabilities()
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate tokens using primary provider."""
        return self.primary_provider.estimate_tokens(text)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model info from primary provider."""
        return self.primary_provider.get_model_info()
    
    async def health_check(self) -> bool:
        """Check health of any provider."""
        for provider in self.providers:
            try:
                if await provider.health_check():
                    return True
            except Exception:
                continue
        return False