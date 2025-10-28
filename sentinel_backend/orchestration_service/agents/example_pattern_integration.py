"""
Example Agent Integration with Pattern Learning

This file demonstrates how to integrate pattern learning and reuse
into existing agents for 30-50% performance improvement.

USAGE:
------
Modify your agents (functional_positive_agent, security_auth_agent, etc.)
to follow this pattern.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class PatternAwareAgent:
    """
    Base agent with pattern learning and reuse capabilities.

    This is an example showing how to enhance existing agents.
    """

    def __init__(
        self,
        agent_type: str,
        pattern_learning_service,
        pattern_reuse_service,
        llm_client
    ):
        """
        Initialize pattern-aware agent.

        Args:
            agent_type: Type of agent (functional-positive, security-auth, etc.)
            pattern_learning_service: Service for extracting and storing patterns
            pattern_reuse_service: Service for finding and adapting patterns
            llm_client: LLM client for generating novel tests
        """
        self.agent_type = agent_type
        self.pattern_learning = pattern_learning_service
        self.pattern_reuse = pattern_reuse_service
        self.llm_client = llm_client

        logger.info(f"{agent_type} agent initialized with pattern learning")

    async def generate_tests(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        count: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generate tests using 50% patterns, 50% novel generation.

        This is the key optimization: reuse proven patterns when available,
        generate fresh tests for novel scenarios.

        Args:
            api_spec: API specification
            endpoint: Target endpoint
            method: HTTP method
            count: Total tests to generate

        Returns:
            List of test cases
        """
        all_tests = []

        # STEP 1: Try to reuse existing patterns (fast path)
        # ================================================
        pattern_count = count // 2  # 50% from patterns

        logger.info(
            f"Searching for {pattern_count} pattern-based tests for "
            f"{method} {endpoint}"
        )

        try:
            pattern_based_tests = await self.pattern_reuse.generate_tests_from_patterns(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                pattern_type=self.agent_type,
                max_tests=pattern_count
            )

            all_tests.extend(pattern_based_tests)

            logger.info(
                f"Generated {len(pattern_based_tests)} tests from patterns "
                f"(saved ~{len(pattern_based_tests) * 2}s of LLM time)"
            )

        except Exception as e:
            logger.warning(f"Pattern generation failed: {e}, falling back to LLM")

        # STEP 2: Generate novel tests using LLM (for remaining count)
        # ============================================================
        novel_count = count - len(all_tests)

        if novel_count > 0:
            logger.info(f"Generating {novel_count} novel tests using LLM")

            novel_tests = await self._generate_with_llm(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                count=novel_count
            )

            all_tests.extend(novel_tests)

        logger.info(
            f"Generated {len(all_tests)} total tests "
            f"({len(pattern_based_tests)} from patterns, "
            f"{novel_count} novel)"
        )

        return all_tests

    async def learn_from_execution(
        self,
        test_case: Dict[str, Any],
        execution_result: Dict[str, Any],
        api_spec: Dict[str, Any]
    ):
        """
        Extract and store patterns from successful test execution.

        Call this after executing tests to feed the learning loop.

        Args:
            test_case: Executed test case
            execution_result: Execution results
            api_spec: API specification
        """
        try:
            # Only learn from successful tests
            if execution_result.get("status") != "success":
                return

            # Extract pattern
            pattern = await self.pattern_learning.extract_pattern_from_test_case(
                test_case=test_case,
                execution_result=execution_result,
                api_spec=api_spec
            )

            if pattern:
                # Store in AgentDB (with deduplication)
                result = await self.pattern_learning.store_pattern(
                    pattern=pattern,
                    deduplicate=True
                )

                # Link test to pattern (for tracking)
                if result["status"] == "success":
                    await self.pattern_learning.link_test_to_pattern(
                        test_case_id=test_case.get("test_id", "unknown"),
                        pattern_id=pattern.pattern_id,
                        contribution_score=1.0
                    )

                logger.info(
                    f"Learned pattern {pattern.pattern_id} from test "
                    f"{test_case.get('test_id', 'unknown')}"
                )

        except Exception as e:
            logger.error(f"Failed to learn from execution: {e}", exc_info=True)

    async def update_pattern_feedback(
        self,
        test_case: Dict[str, Any],
        success: bool,
        execution_time_ms: float
    ):
        """
        Update pattern confidence based on test execution feedback.

        Call this with feedback to improve pattern quality over time.

        Args:
            test_case: Test case that was executed
            success: Whether execution succeeded
            execution_time_ms: Execution time
        """
        try:
            # Get pattern ID from test metadata
            pattern_id = test_case.get("metadata", {}).get("pattern_id")

            if not pattern_id:
                return  # Not a pattern-based test

            # Update confidence
            await self.pattern_learning.update_pattern_confidence(
                pattern_id=pattern_id,
                success=success,
                execution_time_ms=execution_time_ms
            )

            logger.info(
                f"Updated pattern {pattern_id} confidence "
                f"(success={success}, time={execution_time_ms}ms)"
            )

        except Exception as e:
            logger.error(f"Failed to update pattern feedback: {e}", exc_info=True)

    # Private methods

    async def _generate_with_llm(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """
        Generate tests using LLM.

        This is your existing test generation logic.
        Replace this with your actual LLM-based generation.
        """
        # Placeholder - use your existing LLM generation logic here
        tests = []

        for i in range(count):
            test = {
                "test_id": f"llm_test_{datetime.utcnow().timestamp()}_{i}",
                "test_type": self.agent_type,
                "endpoint": endpoint,
                "method": method,
                "description": f"LLM-generated test {i}",
                "assertions": [
                    {"type": "status_code", "expected": 200}
                ],
                "expected_status": 200,
                "metadata": {
                    "generated_from_pattern": False,
                    "generation_method": "llm"
                }
            }
            tests.append(test)

        return tests


# =============================================================================
# INTEGRATION EXAMPLES
# =============================================================================

class FunctionalPositiveAgentWithPatterns(PatternAwareAgent):
    """
    Example: Functional Positive Agent with pattern learning.

    To integrate into your existing agent:
    1. Add pattern_learning_service and pattern_reuse_service to __init__
    2. Replace generate() with generate_tests() logic above
    3. Call learn_from_execution() after test execution
    4. Call update_pattern_feedback() with execution results
    """

    def __init__(
        self,
        pattern_learning_service,
        pattern_reuse_service,
        llm_client
    ):
        super().__init__(
            agent_type="functional-positive",
            pattern_learning_service=pattern_learning_service,
            pattern_reuse_service=pattern_reuse_service,
            llm_client=llm_client
        )

    async def execute(
        self,
        api_spec: Dict[str, Any],
        endpoints: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Execute agent with pattern learning integration.

        This is a complete example of the execution flow.
        """
        all_tests = []
        execution_results = []

        for endpoint_config in endpoints:
            endpoint = endpoint_config["path"]
            method = endpoint_config["method"]

            logger.info(f"Generating tests for {method} {endpoint}")

            # Generate tests (50% patterns, 50% novel)
            tests = await self.generate_tests(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                count=10
            )

            all_tests.extend(tests)

            # Execute tests (your existing execution logic)
            for test in tests:
                exec_result = await self._execute_test(test)
                execution_results.append(exec_result)

                # Learn from successful tests
                await self.learn_from_execution(
                    test_case=test,
                    execution_result=exec_result,
                    api_spec=api_spec
                )

                # Update pattern confidence
                pattern_id = test.get("metadata", {}).get("pattern_id")
                if pattern_id:
                    await self.update_pattern_feedback(
                        test_case=test,
                        success=exec_result.get("status") == "success",
                        execution_time_ms=exec_result.get("latency_ms", 0)
                    )

        return {
            "agent_type": self.agent_type,
            "tests_generated": len(all_tests),
            "pattern_based_tests": sum(
                1 for t in all_tests
                if t.get("metadata", {}).get("generated_from_pattern")
            ),
            "novel_tests": sum(
                1 for t in all_tests
                if not t.get("metadata", {}).get("generated_from_pattern")
            ),
            "execution_results": execution_results
        }

    async def _execute_test(self, test: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single test (placeholder).

        Replace with your actual test execution logic.
        """
        # Placeholder
        return {
            "status": "success",
            "latency_ms": 45.0,
            "assertions": {"passed": 1, "failed": 0}
        }


# =============================================================================
# MIGRATION GUIDE
# =============================================================================

"""
HOW TO MIGRATE EXISTING AGENTS:
================================

1. Add services to agent initialization:

   class YourAgent(BaseAgent):
       def __init__(self, ..., pattern_learning_service, pattern_reuse_service):
           super().__init__(...)
           self.pattern_learning = pattern_learning_service
           self.pattern_reuse = pattern_reuse_service

2. Modify test generation method:

   async def generate_tests(self, api_spec, endpoint, method, count=10):
       # Try patterns first
       pattern_tests = await self.pattern_reuse.generate_tests_from_patterns(
           api_spec=api_spec,
           endpoint=endpoint,
           method=method,
           pattern_type=self.agent_type,
           max_tests=count // 2
       )

       # Generate novel tests for remaining
       novel_count = count - len(pattern_tests)
       novel_tests = await self._generate_with_llm(...)

       return pattern_tests + novel_tests

3. Add learning after execution:

   async def execute(self, ...):
       tests = await self.generate_tests(...)

       for test in tests:
           result = await self._execute_test(test)

           # Learn from successful tests
           if result.get("status") == "success":
               await self.pattern_learning.extract_and_store(
                   test_case=test,
                   execution_result=result,
                   api_spec=api_spec
               )

           # Update pattern confidence
           if test.get("metadata", {}).get("pattern_id"):
               await self.pattern_learning.update_pattern_confidence(
                   pattern_id=test["metadata"]["pattern_id"],
                   success=result.get("status") == "success",
                   execution_time_ms=result.get("latency_ms")
               )

4. Initialize services in orchestration_service/main.py:

   from services.pattern_learning_service import PatternLearningService
   from services.pattern_reuse_service import PatternReuseService
   from agentdb_service.agentdb_client import AgentDBClient
   from agentdb_service.embedding_service import EmbeddingService

   # Initialize
   agentdb = AgentDBClient()
   embedding_service = EmbeddingService()
   pattern_learning = PatternLearningService(agentdb, embedding_service)
   pattern_reuse = PatternReuseService(agentdb, embedding_service)

   # Pass to agents
   agent = FunctionalPositiveAgent(
       ...,
       pattern_learning_service=pattern_learning,
       pattern_reuse_service=pattern_reuse
   )

EXPECTED RESULTS:
=================
- 30-50% reduction in test generation time
- Higher quality tests from proven patterns
- Continuous improvement as more patterns are learned
- Reduced LLM API costs (fewer generation calls)
"""
