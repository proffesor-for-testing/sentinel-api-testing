"""Model-specific prompt templates for optimal performance."""

from typing import Dict, Any, Optional
from .base_template import BasePromptTemplate, PromptTemplate


class OpenAITemplate(BasePromptTemplate):
    """Prompt templates optimized for OpenAI models."""
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load OpenAI-specific templates."""
        return {
            "test_generation": PromptTemplate(
                system_prompt="""You are an expert API tester using OpenAPI specifications.
Your task is to generate comprehensive test cases that cover:
1. Valid inputs (happy path)
2. Edge cases
3. Invalid inputs
4. Boundary conditions
Use structured thinking and be thorough.""",
                user_prompt="""Generate test cases for this API:
Endpoint: {endpoint}
Method: {method}
Parameters: {parameters}
Schema: {schema}

Provide test cases in JSON format with clear descriptions.""",
                temperature=0.7,
                max_tokens=2000
            ),
            "function_calling": PromptTemplate(
                system_prompt="You are a helpful assistant that uses functions to complete tasks.",
                user_prompt="Use the available functions to: {task}",
                temperature=0.3
            )
        }
    
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for GPT models."""
        template = self.get_template(task) or self.get_default_template(task)
        
        # GPT-4 can handle longer contexts
        if context.get("model", "").startswith("gpt-4"):
            template.max_tokens = 4000
        
        # Use lower temperature for code generation
        if "code" in task or "generation" in task:
            template.temperature = 0.3
        
        return template


class AnthropicTemplate(BasePromptTemplate):
    """Prompt templates optimized for Anthropic Claude models."""
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load Claude-specific templates."""
        return {
            "test_generation": PromptTemplate(
                system_prompt="""You are Claude, an expert API tester. You excel at:
- Systematic analysis of API specifications
- Generating comprehensive test coverage
- Finding edge cases and potential issues
- Writing clear, maintainable test cases""",
                user_prompt="""I need you to generate test cases for an API endpoint.

<api_details>
Endpoint: {endpoint}
Method: {method}
Parameters: {parameters}
Schema: {schema}
Description: {description}
</api_details>

Please generate:
1. Positive test cases (valid inputs)
2. Negative test cases (invalid inputs)
3. Edge cases
4. Security-relevant test cases

Format your response as structured JSON.""",
                temperature=0.7,
                max_tokens=4000
            ),
            "reasoning": PromptTemplate(
                system_prompt="You are Claude, capable of deep reasoning and analysis.",
                user_prompt="""Let me think through this step-by-step:

Task: {task}
Context: {context}

I'll analyze this systematically and provide a comprehensive solution.""",
                temperature=0.5
            )
        }
    
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for Claude models."""
        template = self.get_template(task) or self.get_default_template(task)
        
        # Claude handles XML-style tags well
        if "analysis" in task or "reasoning" in task:
            template.user_prompt = f"<task>\n{template.user_prompt}\n</task>"
        
        # Claude 4 models have enhanced capabilities
        if "claude-4" in context.get("model", "").lower():
            template.temperature = 0.6  # Slightly lower for consistency
            if "opus" in context.get("model", "").lower():
                template.max_tokens = 4096  # Max for Opus
        
        return template


class GoogleTemplate(BasePromptTemplate):
    """Prompt templates optimized for Google Gemini models."""
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load Gemini-specific templates."""
        return {
            "test_generation": PromptTemplate(
                system_prompt="""You are an AI assistant specialized in API testing.
Focus on generating practical, executable test cases.
Consider real-world scenarios and common integration issues.""",
                user_prompt="""Generate comprehensive test cases for this API:

**Endpoint:** {endpoint}
**Method:** {method}
**Parameters:**
```json
{parameters}
```
**Schema:**
```json
{schema}
```

Generate test cases covering:
- Normal operations
- Error conditions
- Performance considerations
- Security implications""",
                temperature=0.7,
                max_tokens=8000  # Gemini supports larger outputs
            ),
            "multimodal": PromptTemplate(
                system_prompt="You are a multimodal AI that can analyze both text and images.",
                user_prompt="Analyze the provided content: {content}",
                temperature=0.5
            )
        }
    
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for Gemini models."""
        template = self.get_template(task) or self.get_default_template(task)
        
        # Gemini 2.5 Pro and 1.5 Pro have massive context windows
        if "gemini-2.5-pro" in context.get("model", "").lower() or "gemini-1.5-pro" in context.get("model", "").lower():
            template.max_tokens = 8192
        
        # Use markdown formatting for better structure
        if "generation" in task:
            template.user_prompt = template.user_prompt.replace("{parameters}", "```json\n{parameters}\n```")
        
        return template


class MistralTemplate(BasePromptTemplate):
    """Prompt templates optimized for Mistral models."""
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load Mistral-specific templates."""
        return {
            "test_generation": PromptTemplate(
                system_prompt="You are an expert API tester. Be concise and precise.",
                user_prompt="""Generate test cases for:
- Endpoint: {endpoint}
- Method: {method}
- Parameters: {parameters}

Focus on:
1. Functional correctness
2. Edge cases
3. Error handling

Output format: JSON test cases""",
                temperature=0.6,
                max_tokens=2000
            ),
            "code_generation": PromptTemplate(
                system_prompt="You are Codestral, optimized for code generation.",
                user_prompt="Generate {language} code for: {task}",
                temperature=0.3
            )
        }
    
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for Mistral models."""
        template = self.get_template(task) or self.get_default_template(task)
        
        # Codestral is optimized for code
        if "codestral" in context.get("model", "").lower():
            template.temperature = 0.2
            template.system_prompt = "You are Codestral, a code-specialized AI."
        
        # Mistral Large can handle more complex prompts
        if "large" in context.get("model", "").lower():
            template.max_tokens = 4000
        
        return template


class OllamaTemplate(BasePromptTemplate):
    """Prompt templates optimized for open-source models via Ollama."""
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load templates for open-source models."""
        return {
            "test_generation": PromptTemplate(
                user_prompt="""Generate API test cases.
Endpoint: {endpoint}
Method: {method}
Parameters: {parameters}

Create tests for:
- Valid inputs
- Invalid inputs
- Edge cases

Format: JSON""",
                temperature=0.7,
                max_tokens=2000
            ),
            "reasoning": PromptTemplate(
                user_prompt="""Task: {task}
Let me solve this step by step:
1. Understand the requirements
2. Analyze the problem
3. Generate solution
4. Verify correctness""",
                temperature=0.5
            )
        }
    
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for open-source models."""
        template = self.get_template(task) or self.get_default_template(task)
        model = context.get("model", "").lower()
        
        # DeepSeek-R1 excels at reasoning
        if "deepseek" in model and "r1" in model:
            template.temperature = 0.4
            template.user_prompt = f"<reasoning>\n{template.user_prompt}\n</reasoning>"
        
        # Llama models work well with structured prompts
        elif "llama" in model:
            template.temperature = 0.6
            if "70b" in model or "405b" in model:
                template.max_tokens = 4000
        
        # Qwen models are good at multilingual
        elif "qwen" in model:
            template.temperature = 0.7
            if "coder" in model:
                template.temperature = 0.3  # Lower for code
        
        # Phi models are efficient but smaller
        elif "phi" in model:
            template.max_tokens = 1500
            template.temperature = 0.5
        
        return template


def get_template_for_model(provider: str, model: str) -> BasePromptTemplate:
    """Get the appropriate template class for a model."""
    provider_lower = provider.lower()
    
    if provider_lower == "openai":
        return OpenAITemplate()
    elif provider_lower == "anthropic":
        return AnthropicTemplate()
    elif provider_lower == "google":
        return GoogleTemplate()
    elif provider_lower == "mistral":
        return MistralTemplate()
    elif provider_lower in ["ollama", "vllm"]:
        return OllamaTemplate()
    else:
        # Return a basic template for unknown providers
        return OpenAITemplate()  # Default to OpenAI style