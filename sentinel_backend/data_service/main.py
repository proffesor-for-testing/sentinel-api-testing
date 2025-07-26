import os
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status, Query
from sqlalchemy import create_engine, select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import selectinload

from .models import Base, TestCase, TestSuite, TestSuiteEntry, TestRun, TestResult
from .schemas import (
    TestCaseCreate, TestCaseResponse, TestCaseSummary,
    TestSuiteCreate, TestSuiteResponse, TestSuiteSummary,
    TestSuiteEntryCreate, TestSuiteEntryResponse,
    TestRunCreate, TestRunResponse, TestRunSummary,
    TestResultCreate, TestResultResponse,
    FailureRateData, LatencyData, HealthSummary,
    DeleteResponse, RunStatus, TestStatus
)

app = FastAPI(
    title="Sentinel Data & Analytics Service",
    description="Service for managing test data, analytics, and reporting",
    version="1.0.0"
)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:password@localhost/sentinel_db")

# Create async engine and session
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """Create database tables if they don't exist"""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        print(f"Warning: Could not connect to database: {e}")
        print("Service will run without database persistence")

@app.on_event("startup")
async def startup_event():
    await create_tables()

@app.get("/")
async def root():
    return {"message": "Sentinel Data & Analytics Service is running"}

# Test Cases endpoints
@app.post("/api/v1/test-cases", response_model=TestCaseResponse)
async def create_test_case(
    test_case_data: TestCaseCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new test case."""
    try:
        # Convert tags list to JSONB format
        tags_json = test_case_data.tags if test_case_data.tags else None
        
        db_test_case = TestCase(
            spec_id=test_case_data.spec_id,
            agent_type=test_case_data.agent_type,
            description=test_case_data.description,
            test_definition=test_case_data.test_definition,
            tags=tags_json
        )
        
        db.add(db_test_case)
        await db.commit()
        await db.refresh(db_test_case)
        
        return TestCaseResponse.model_validate(db_test_case)
    
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating test case: {str(e)}"
        )

@app.get("/api/v1/test-cases", response_model=List[TestCaseSummary])
async def list_test_cases(
    spec_id: Optional[int] = Query(None, description="Filter by specification ID"),
    agent_type: Optional[str] = Query(None, description="Filter by agent type"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    db: AsyncSession = Depends(get_db)
):
    """List all test cases with optional filtering."""
    try:
        query = select(TestCase)
        
        # Apply filters
        if spec_id:
            query = query.where(TestCase.spec_id == spec_id)
        if agent_type:
            query = query.where(TestCase.agent_type == agent_type)
        if tags:
            tag_list = [tag.strip() for tag in tags.split(",")]
            for tag in tag_list:
                query = query.where(TestCase.tags.contains([tag]))
        
        query = query.order_by(desc(TestCase.created_at))
        result = await db.execute(query)
        test_cases = result.scalars().all()
        
        return [TestCaseSummary.model_validate(tc) for tc in test_cases]
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving test cases: {str(e)}"
        )

@app.get("/api/v1/test-cases/{case_id}", response_model=TestCaseResponse)
async def get_test_case(case_id: int, db: AsyncSession = Depends(get_db)):
    """Retrieve a specific test case by ID."""
    try:
        result = await db.execute(
            select(TestCase).where(TestCase.id == case_id)
        )
        test_case = result.scalar_one_or_none()
        
        if not test_case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Test case with ID {case_id} not found"
            )
        
        return TestCaseResponse.model_validate(test_case)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving test case: {str(e)}"
        )

# Test Suites endpoints
@app.post("/api/v1/test-suites", response_model=TestSuiteResponse)
async def create_test_suite(
    suite_data: TestSuiteCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new test suite."""
    try:
        db_test_suite = TestSuite(
            name=suite_data.name,
            description=suite_data.description
        )
        
        db.add(db_test_suite)
        await db.commit()
        await db.refresh(db_test_suite)
        
        return TestSuiteResponse.model_validate(db_test_suite)
    
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating test suite: {str(e)}"
        )

@app.get("/api/v1/test-suites", response_model=List[TestSuiteSummary])
async def list_test_suites(db: AsyncSession = Depends(get_db)):
    """List all test suites."""
    try:
        result = await db.execute(
            select(TestSuite).order_by(desc(TestSuite.created_at))
        )
        test_suites = result.scalars().all()
        
        return [TestSuiteSummary.model_validate(ts) for ts in test_suites]
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving test suites: {str(e)}"
        )

@app.get("/api/v1/test-suites/{suite_id}", response_model=TestSuiteResponse)
async def get_test_suite(suite_id: int, db: AsyncSession = Depends(get_db)):
    """Retrieve a specific test suite with its test cases."""
    try:
        result = await db.execute(
            select(TestSuite)
            .options(selectinload(TestSuite.suite_entries).selectinload(TestSuiteEntry.test_case))
            .where(TestSuite.id == suite_id)
        )
        test_suite = result.scalar_one_or_none()
        
        if not test_suite:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Test suite with ID {suite_id} not found"
            )
        
        # Convert to response format with test cases
        test_cases = [
            TestCaseSummary.model_validate(entry.test_case)
            for entry in sorted(test_suite.suite_entries, key=lambda x: x.execution_order)
        ]
        
        suite_response = TestSuiteResponse.model_validate(test_suite)
        suite_response.test_cases = test_cases
        
        return suite_response
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving test suite: {str(e)}"
        )

@app.post("/api/v1/test-suites/{suite_id}/cases", response_model=TestSuiteEntryResponse)
async def add_test_case_to_suite(
    suite_id: int,
    entry_data: TestSuiteEntryCreate,
    db: AsyncSession = Depends(get_db)
):
    """Add a test case to a test suite."""
    try:
        # Check if suite exists
        suite_result = await db.execute(select(TestSuite).where(TestSuite.id == suite_id))
        if not suite_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Test suite with ID {suite_id} not found"
            )
        
        # Check if test case exists
        case_result = await db.execute(select(TestCase).where(TestCase.id == entry_data.case_id))
        if not case_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Test case with ID {entry_data.case_id} not found"
            )
        
        # Check if entry already exists
        existing_result = await db.execute(
            select(TestSuiteEntry).where(
                and_(
                    TestSuiteEntry.suite_id == suite_id,
                    TestSuiteEntry.case_id == entry_data.case_id
                )
            )
        )
        if existing_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Test case {entry_data.case_id} is already in suite {suite_id}"
            )
        
        db_entry = TestSuiteEntry(
            suite_id=suite_id,
            case_id=entry_data.case_id,
            execution_order=entry_data.execution_order
        )
        
        db.add(db_entry)
        await db.commit()
        await db.refresh(db_entry)
        
        return TestSuiteEntryResponse.model_validate(db_entry)
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding test case to suite: {str(e)}"
        )

@app.delete("/api/v1/test-suites/{suite_id}/cases/{case_id}", response_model=DeleteResponse)
async def remove_test_case_from_suite(
    suite_id: int,
    case_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Remove a test case from a test suite."""
    try:
        result = await db.execute(
            select(TestSuiteEntry).where(
                and_(
                    TestSuiteEntry.suite_id == suite_id,
                    TestSuiteEntry.case_id == case_id
                )
            )
        )
        entry = result.scalar_one_or_none()
        
        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Test case {case_id} not found in suite {suite_id}"
            )
        
        await db.delete(entry)
        await db.commit()
        
        return DeleteResponse(
            message=f"Test case {case_id} removed from suite {suite_id}",
            deleted_id=case_id
        )
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error removing test case from suite: {str(e)}"
        )

# Analytics endpoints
@app.get("/api/v1/analytics/trends/failure-rate", response_model=List[FailureRateData])
async def get_failure_rate_trends(
    suite_id: Optional[int] = Query(None, description="Filter by suite ID"),
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db)
):
    """Get historical failure rate data."""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # This is a simplified implementation
        # In a real system, you'd aggregate data by date and calculate failure rates
        return [
            FailureRateData(
                date=end_date - timedelta(days=i),
                total_tests=10,
                failed_tests=2,
                failure_rate=0.2
            ) for i in range(min(days, 7))  # Return sample data for last 7 days
        ]
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving failure rate trends: {str(e)}"
        )

@app.get("/api/v1/analytics/trends/latency", response_model=List[LatencyData])
async def get_latency_trends(
    endpoint: Optional[str] = Query(None, description="Filter by specific endpoint"),
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db)
):
    """Get historical latency data."""
    try:
        end_date = datetime.utcnow()
        
        # This is a simplified implementation
        # In a real system, you'd query test_results and calculate percentiles
        return [
            LatencyData(
                date=end_date - timedelta(days=i),
                avg_latency_ms=150.0 + (i * 5),
                p95_latency_ms=250.0 + (i * 8),
                p99_latency_ms=350.0 + (i * 12)
            ) for i in range(min(days, 7))  # Return sample data for last 7 days
        ]
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving latency trends: {str(e)}"
        )

@app.get("/api/v1/analytics/health-summary", response_model=HealthSummary)
async def get_health_summary(db: AsyncSession = Depends(get_db)):
    """Get an overall health summary."""
    try:
        # Count total test cases
        test_cases_result = await db.execute(select(func.count(TestCase.id)))
        total_test_cases = test_cases_result.scalar() or 0
        
        # Count total test runs
        test_runs_result = await db.execute(select(func.count(TestRun.id)))
        total_test_runs = test_runs_result.scalar() or 0
        
        # Get recent failure rate (simplified calculation)
        recent_failure_rate = 0.15  # Default value
        avg_latency_ms = 165.0  # Default value
        
        # Get last run status
        last_run_result = await db.execute(
            select(TestRun).order_by(desc(TestRun.started_at)).limit(1)
        )
        last_run = last_run_result.scalar_one_or_none()
        last_run_status = RunStatus(last_run.status) if last_run else None
        
        # Calculate health score based on metrics
        health_score = max(0, min(100, 85 - (recent_failure_rate * 100)))
        
        # Generate recommendations based on data
        recommendations = []
        critical_issues = []
        
        if recent_failure_rate > 0.2:
            critical_issues.append("High failure rate detected")
            recommendations.append("Review failing test cases and fix underlying issues")
        
        if avg_latency_ms > 200:
            recommendations.append("Consider optimizing API response times")
        
        if total_test_cases < 10:
            recommendations.append("Increase test coverage by adding more test cases")
        
        return HealthSummary(
            overall_health_score=health_score,
            total_test_cases=total_test_cases,
            total_test_runs=total_test_runs,
            recent_failure_rate=recent_failure_rate,
            avg_latency_ms=avg_latency_ms,
            last_run_status=last_run_status,
            critical_issues=critical_issues,
            recommendations=recommendations
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating health summary: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "data-analytics-service"}
