"""
Validation Script for Pattern Learning Services

Run this to verify the implementation works correctly.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import services
try:
    # Try absolute imports first
    try:
        from sentinel_backend.orchestration_service.services.pattern_learning_service import (
            PatternLearningService,
            TestPattern
        )
        from sentinel_backend.orchestration_service.services.pattern_reuse_service import (
            PatternReuseService,
            PatternMatch
        )
        from sentinel_backend.agentdb_service.agentdb_client import AgentDBClient
        from sentinel_backend.agentdb_service.embedding_service import EmbeddingService
    except ImportError:
        # Fall back to relative imports
        from pattern_learning_service import PatternLearningService, TestPattern
        from pattern_reuse_service import PatternReuseService, PatternMatch
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agentdb_service"))
        from agentdb_client import AgentDBClient
        from embedding_service import EmbeddingService

    print("✅ All imports successful!")
except ImportError as e:
    print(f"❌ Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


async def validate_services():
    """Validate pattern learning services."""
    print("\n" + "="*60)
    print("PATTERN LEARNING SERVICES VALIDATION")
    print("="*60 + "\n")

    # Initialize services
    print("1. Initializing services...")
    try:
        agentdb = AgentDBClient(collection_prefix="test")
        embedding_service = EmbeddingService()
        pattern_learning = PatternLearningService(
            agentdb_client=agentdb,
            embedding_service=embedding_service
        )
        pattern_reuse = PatternReuseService(
            agentdb_client=agentdb,
            embedding_service=embedding_service,
            similarity_threshold=0.7
        )
        print("   ✅ Services initialized successfully\n")
    except Exception as e:
        print(f"   ❌ Failed to initialize services: {e}")
        return False

    # Test 1: Extract pattern from test case
    print("2. Testing pattern extraction...")
    try:
        test_case = {
            "test_id": "test_001",
            "test_type": "functional-positive",
            "endpoint": "/api/v1/users/123",
            "method": "GET",
            "query_params": {"include": "profile"},
            "headers": {"Authorization": "Bearer token"},
            "assertions": [
                {"type": "status_code", "expected": 200}
            ],
            "expected_status": 200,
            "auth_required": True
        }

        execution_result = {
            "status": "success",
            "latency_ms": 45.2,
            "assertions": {"passed": 1, "failed": 0}
        }

        api_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/users/{id}": {
                    "get": {"summary": "Get user"}
                }
            }
        }

        pattern = await pattern_learning.extract_pattern_from_test_case(
            test_case=test_case,
            execution_result=execution_result,
            api_spec=api_spec
        )

        if pattern:
            print(f"   ✅ Pattern extracted successfully")
            print(f"      - Pattern ID: {pattern.pattern_id}")
            print(f"      - Pattern type: {pattern.pattern_type}")
            print(f"      - Endpoint: {pattern.endpoint_pattern}")
            print(f"      - Method: {pattern.http_method}")
            print(f"      - Confidence: {pattern.confidence_score}")
            print(f"      - Embedding dimension: {len(pattern.embedding)}\n")
        else:
            print("   ❌ Failed to extract pattern\n")
            return False

    except Exception as e:
        print(f"   ❌ Pattern extraction failed: {e}\n")
        return False

    # Test 2: Store pattern
    print("3. Testing pattern storage...")
    try:
        result = await pattern_learning.store_pattern(
            pattern=pattern,
            deduplicate=False
        )

        if result["status"] == "success":
            print(f"   ✅ Pattern stored successfully")
            print(f"      - Pattern ID: {result['pattern_id']}")
            print(f"      - Collection: {result.get('collection', 'N/A')}\n")
        else:
            print(f"   ❌ Failed to store pattern: {result}\n")
            return False

    except Exception as e:
        print(f"   ❌ Pattern storage failed: {e}\n")
        return False

    # Test 3: Find similar patterns
    print("4. Testing pattern search...")
    try:
        matches = await pattern_reuse.find_similar_patterns(
            api_spec=api_spec,
            endpoint="/api/v1/users/456",
            method="GET",
            top_k=5
        )

        print(f"   ✅ Pattern search completed")
        print(f"      - Found {len(matches)} matches")

        if matches:
            for i, match in enumerate(matches[:3], 1):
                print(f"      - Match {i}:")
                print(f"        Similarity: {match.similarity_score:.3f}")
                print(f"        Confidence: {match.confidence_score:.3f}")
                print(f"        Combined score: {match.combined_score:.3f}")

        print()

    except Exception as e:
        print(f"   ❌ Pattern search failed: {e}\n")
        return False

    # Test 4: Adapt pattern
    print("5. Testing pattern adaptation...")
    try:
        # Use dummy match if no real matches
        if not matches:
            print("   ⚠️  No matches found, skipping adaptation test\n")
        else:
            adapted = await pattern_reuse.adapt_pattern_to_context(
                pattern_match=matches[0],
                target_endpoint="/api/v1/users/789",
                target_method="GET",
                api_spec=api_spec
            )

            if adapted and adapted.adapted_test_case:
                print(f"   ✅ Pattern adapted successfully")
                print(f"      - Original pattern: {adapted.original_pattern_id}")
                print(f"      - New endpoint: {adapted.adapted_test_case['endpoint']}")
                print(f"      - Adaptation confidence: {adapted.confidence:.3f}")
                print(f"      - Adaptation notes: {len(adapted.adaptation_notes)}\n")
            else:
                print("   ❌ Failed to adapt pattern\n")
                return False

    except Exception as e:
        print(f"   ❌ Pattern adaptation failed: {e}\n")
        return False

    # Test 5: Update confidence
    print("6. Testing confidence update...")
    try:
        await pattern_learning.update_pattern_confidence(
            pattern_id=pattern.pattern_id,
            success=True,
            execution_time_ms=42.0
        )
        print(f"   ✅ Confidence updated successfully\n")

    except Exception as e:
        print(f"   ❌ Confidence update failed: {e}\n")
        return False

    # Test 6: Get statistics
    print("7. Testing pattern statistics...")
    try:
        stats = await pattern_learning.get_pattern_statistics()
        print(f"   ✅ Statistics retrieved successfully")
        print(f"      - Total patterns: {stats.get('total_patterns', 0)}")
        print(f"      - Collection: {stats.get('collection', 'N/A')}")
        print(f"      - Dimension: {stats.get('embedding_dimension', 0)}\n")

    except Exception as e:
        print(f"   ❌ Statistics retrieval failed: {e}\n")
        return False

    print("="*60)
    print("✅ ALL VALIDATION TESTS PASSED!")
    print("="*60)
    print("\nPattern Learning Services are working correctly.")
    print("\nNext steps:")
    print("1. Integrate into agents (see agents/example_pattern_integration.py)")
    print("2. Run full test suite: pytest tests/integration/learning/")
    print("3. Monitor pattern statistics in production")
    print()

    return True


if __name__ == "__main__":
    success = asyncio.run(validate_services())
    sys.exit(0 if success else 1)
