"""
FastAPI endpoints for pattern recognition system.

Provides REST API for:
- Pattern extraction and storage
- Pattern matching and search
- Pattern-based test generation
- Pattern analytics and insights
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from ..services.pattern_recognition_service import (
    PatternRecognitionService,
    Pattern,
    PatternType
)
from ..services.pattern_storage import PatternStorage
from ..services.pattern_test_generator import PatternTestGenerator
from ..services.pattern_analytics import PatternAnalytics

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/patterns", tags=["patterns"])

# Initialize services (would be dependency injected in production)
pattern_storage = PatternStorage()
pattern_service = PatternRecognitionService(vector_db_client=None)
pattern_generator = PatternTestGenerator(pattern_service)
pattern_analytics = PatternAnalytics()


# Request/Response models

class ExtractPatternRequest(BaseModel):
    """Request to extract patterns from test execution."""
    test_case: Dict[str, Any] = Field(..., description="Test case definition")
    execution_result: Dict[str, Any] = Field(..., description="Execution result")
    api_spec: Dict[str, Any] = Field(..., description="API specification")


class PatternMatchRequest(BaseModel):
    """Request to find matching patterns."""
    api_spec: Dict[str, Any] = Field(..., description="API specification")
    endpoint: str = Field(..., description="Endpoint path")
    method: str = Field(..., description="HTTP method")
    similarity_threshold: float = Field(0.7, ge=0.0, le=1.0, description="Similarity threshold")


class GenerateTestRequest(BaseModel):
    """Request to generate tests from patterns."""
    api_spec: Dict[str, Any] = Field(..., description="API specification")
    endpoint: str = Field(..., description="Endpoint path")
    method: str = Field(..., description="HTTP method")
    max_patterns: int = Field(5, ge=1, le=20, description="Maximum patterns to use")
    similarity_threshold: float = Field(0.7, ge=0.0, le=1.0, description="Similarity threshold")


class PatternFeedbackRequest(BaseModel):
    """Feedback on pattern usage."""
    pattern_id: str = Field(..., description="Pattern identifier")
    success: bool = Field(..., description="Whether usage was successful")
    execution_time: Optional[float] = Field(None, description="Execution time in ms")


class DuplicateReductionRequest(BaseModel):
    """Request to calculate duplicate reduction."""
    traditional_test_count: int = Field(..., ge=0)
    pattern_based_test_count: int = Field(..., ge=0)
    unique_test_count: int = Field(..., ge=0)


# Endpoints

@router.post("/extract", response_model=Dict[str, Any])
async def extract_patterns(request: ExtractPatternRequest):
    """
    Extract patterns from a test case and its execution result.

    This endpoint analyzes test cases and their outcomes to learn new patterns.
    """
    try:
        patterns = await pattern_service.extract_pattern_from_test(
            test_case=request.test_case,
            execution_result=request.execution_result,
            api_spec=request.api_spec
        )

        # Store extracted patterns
        for pattern in patterns:
            await pattern_storage.store_pattern(
                pattern_id=pattern.pattern_id,
                pattern_data=pattern.dict(),
                embedding=pattern.embedding or []
            )

        return {
            "success": True,
            "patterns_extracted": len(patterns),
            "patterns": [p.dict() for p in patterns]
        }

    except Exception as e:
        logger.error(f"Error extracting patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/match", response_model=Dict[str, Any])
async def find_matching_patterns(request: PatternMatchRequest):
    """
    Find patterns that match the given API specification.

    Returns patterns sorted by similarity and confidence.
    """
    try:
        matches = await pattern_service.find_matching_patterns(
            api_spec=request.api_spec,
            endpoint=request.endpoint,
            method=request.method,
            similarity_threshold=request.similarity_threshold
        )

        return {
            "success": True,
            "matches_found": len(matches),
            "matches": [
                {
                    "pattern": m.pattern.dict(),
                    "similarity_score": m.similarity_score,
                    "match_reason": m.match_reason,
                    "confidence": m.confidence
                }
                for m in matches
            ]
        }

    except Exception as e:
        logger.error(f"Error finding matching patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-tests", response_model=Dict[str, Any])
async def generate_tests_from_patterns(request: GenerateTestRequest):
    """
    Generate test cases using matched patterns.

    This reduces duplicate test generation by reusing proven patterns.
    """
    try:
        tests = await pattern_generator.generate_tests_from_patterns(
            api_spec=request.api_spec,
            endpoint=request.endpoint,
            method=request.method,
            max_patterns=request.max_patterns,
            similarity_threshold=request.similarity_threshold
        )

        return {
            "success": True,
            "tests_generated": len(tests),
            "tests": tests,
            "generation_method": "pattern_based"
        }

    except Exception as e:
        logger.error(f"Error generating tests from patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-suite", response_model=Dict[str, Any])
async def generate_test_suite(api_spec: Dict[str, Any]):
    """
    Generate a complete test suite using patterns for all endpoints.
    """
    try:
        suite = await pattern_generator.generate_test_suite_from_patterns(
            api_spec=api_spec
        )

        return {
            "success": True,
            "test_suite": suite
        }

    except Exception as e:
        logger.error(f"Error generating test suite: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback", response_model=Dict[str, Any])
async def submit_pattern_feedback(request: PatternFeedbackRequest):
    """
    Submit feedback on pattern usage for continuous learning.
    """
    try:
        await pattern_service.update_pattern_feedback(
            pattern_id=request.pattern_id,
            success=request.success,
            execution_time=request.execution_time
        )

        # Record analytics
        pattern_analytics.record_usage(
            pattern_id=request.pattern_id,
            test_generated=True,
            generation_time_ms=request.execution_time or 0,
            success=request.success
        )

        return {
            "success": True,
            "message": "Feedback recorded successfully"
        }

    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", response_model=Dict[str, Any])
async def get_pattern_statistics():
    """
    Get comprehensive statistics about pattern usage and effectiveness.
    """
    try:
        stats = await pattern_service.get_pattern_statistics()

        return {
            "success": True,
            "statistics": stats
        }

    except Exception as e:
        logger.error(f"Error getting pattern statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/dashboard", response_model=Dict[str, Any])
async def get_analytics_dashboard():
    """
    Get dashboard metrics for pattern analytics.
    """
    try:
        dashboard = pattern_analytics.get_dashboard_metrics()

        return {
            "success": True,
            "dashboard": dashboard
        }

    except Exception as e:
        logger.error(f"Error getting analytics dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analytics/duplicate-reduction", response_model=Dict[str, Any])
async def calculate_duplicate_reduction(request: DuplicateReductionRequest):
    """
    Calculate duplicate reduction achieved by pattern-based generation.
    """
    try:
        metrics = pattern_analytics.calculate_duplicate_reduction(
            traditional_test_count=request.traditional_test_count,
            pattern_based_test_count=request.pattern_based_test_count,
            unique_test_count=request.unique_test_count
        )

        return {
            "success": True,
            "reduction_metrics": metrics
        }

    except Exception as e:
        logger.error(f"Error calculating duplicate reduction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/effectiveness", response_model=Dict[str, Any])
async def get_effectiveness_report(
    pattern_id: Optional[str] = Query(None, description="Specific pattern ID"),
    time_window_hours: int = Query(24, ge=1, le=720, description="Time window in hours")
):
    """
    Get effectiveness report for patterns.
    """
    try:
        report = pattern_analytics.get_pattern_effectiveness_report(
            pattern_id=pattern_id,
            time_window_hours=time_window_hours
        )

        return {
            "success": True,
            "report": report
        }

    except Exception as e:
        logger.error(f"Error getting effectiveness report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/trends", response_model=Dict[str, Any])
async def get_usage_trends(
    time_window_hours: int = Query(168, ge=1, le=720, description="Time window in hours")
):
    """
    Get usage trends over time.
    """
    try:
        trends = pattern_analytics.get_usage_trends(time_window_hours=time_window_hours)

        return {
            "success": True,
            "trends": trends
        }

    except Exception as e:
        logger.error(f"Error getting usage trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{pattern_id}", response_model=Dict[str, Any])
async def get_pattern(pattern_id: str):
    """
    Get a specific pattern by ID.
    """
    try:
        pattern_data = await pattern_storage.retrieve_pattern(pattern_id)

        if not pattern_data:
            raise HTTPException(status_code=404, detail="Pattern not found")

        return {
            "success": True,
            "pattern": pattern_data
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting pattern: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=Dict[str, Any])
async def list_patterns(
    pattern_type: Optional[str] = Query(None, description="Filter by pattern type"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """
    List patterns with optional filtering.
    """
    try:
        patterns = await pattern_storage.list_patterns(
            pattern_type=pattern_type,
            limit=limit,
            offset=offset
        )

        return {
            "success": True,
            "count": len(patterns),
            "patterns": patterns,
            "pagination": {
                "limit": limit,
                "offset": offset
            }
        }

    except Exception as e:
        logger.error(f"Error listing patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{pattern_id}", response_model=Dict[str, Any])
async def delete_pattern(pattern_id: str):
    """
    Delete a pattern by ID.
    """
    try:
        success = await pattern_storage.delete_pattern(pattern_id)

        if not success:
            raise HTTPException(status_code=404, detail="Pattern not found")

        return {
            "success": True,
            "message": f"Pattern {pattern_id} deleted successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting pattern: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/suggest-improvements", response_model=Dict[str, Any])
async def suggest_test_improvements(
    test_case: Dict[str, Any],
    api_spec: Dict[str, Any]
):
    """
    Suggest improvements to a test case based on patterns.
    """
    try:
        suggestions = await pattern_generator.suggest_test_improvements(
            test_case=test_case,
            api_spec=api_spec
        )

        return {
            "success": True,
            "suggestions_count": len(suggestions),
            "suggestions": suggestions
        }

    except Exception as e:
        logger.error(f"Error suggesting improvements: {e}")
        raise HTTPException(status_code=500, detail=str(e))
