import os
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status, Query
from sqlalchemy import create_engine, select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import selectinload
import sys
import os

from config.settings import get_database_settings, get_application_settings

from models import Base, TestCase, TestSuite, TestSuiteEntry, TestRun, TestResult
from schemas import (
    TestCaseCreate, TestCaseResponse, TestCaseSummary,
    TestSuiteCreate, TestSuiteResponse, TestSuiteSummary,
    TestSuiteEntryCreate, TestSuiteEntryResponse,
    TestRunCreate, TestRunResponse, TestRunSummary,
    TestResultCreate, TestResultResponse,
    FailureRateData, LatencyData, HealthSummary,
    DeleteResponse, RunStatus, TestStatus
)

# Get configuration settings
db_settings = get_database_settings()
app_settings = get_application_settings()

app = FastAPI(
    title="Sentinel Data & Analytics Service",
    description="Service for managing test data, analytics, and reporting",
    version=app_settings.app_version
)

# Create async engine and session with configuration
engine = create_async_engine(
    db_settings.url,
    pool_size=db_settings.pool_size,
    max_overflow=db_settings.max_overflow,
    pool_timeout=db_settings.pool_timeout,
    pool_recycle=db_settings.pool_recycle
)
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

@app.put("/api/v1/test-cases/{case_id}", response_model=TestCaseResponse)
async def update_test_case(
    case_id: int,
    test_case_data: TestCaseCreate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing test case."""
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
        
        # Update fields
        test_case.spec_id = test_case_data.spec_id
        test_case.agent_type = test_case_data.agent_type
        test_case.description = test_case_data.description
        test_case.test_definition = test_case_data.test_definition
        test_case.tags = test_case_data.tags if test_case_data.tags else None
        test_case.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(test_case)
        
        return TestCaseResponse.model_validate(test_case)
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating test case: {str(e)}"
        )

@app.delete("/api/v1/test-cases/{case_id}", response_model=DeleteResponse)
async def delete_test_case(case_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a test case."""
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
        
        await db.delete(test_case)
        await db.commit()
        
        return DeleteResponse(
            message=f"Test case {case_id} deleted successfully",
            deleted_id=case_id
        )
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting test case: {str(e)}"
        )

@app.post("/api/v1/test-cases/bulk-update")
async def bulk_update_test_cases(
    updates: dict,
    db: AsyncSession = Depends(get_db)
):
    """Bulk update test cases (add/remove tags, change status, etc.)."""
    try:
        case_ids = updates.get("case_ids", [])
        action = updates.get("action")
        data = updates.get("data", {})
        
        if not case_ids or not action:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="case_ids and action are required"
            )
        
        # Get test cases
        result = await db.execute(
            select(TestCase).where(TestCase.id.in_(case_ids))
        )
        test_cases = result.scalars().all()
        
        if not test_cases:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No test cases found with provided IDs"
            )
        
        updated_count = 0
        
        for test_case in test_cases:
            if action == "add_tags":
                new_tags = data.get("tags", [])
                existing_tags = test_case.tags or []
                test_case.tags = list(set(existing_tags + new_tags))
                updated_count += 1
            
            elif action == "remove_tags":
                tags_to_remove = data.get("tags", [])
                existing_tags = test_case.tags or []
                test_case.tags = [tag for tag in existing_tags if tag not in tags_to_remove]
                updated_count += 1
            
            elif action == "set_tags":
                test_case.tags = data.get("tags", [])
                updated_count += 1
            
            test_case.updated_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "message": f"Successfully updated {updated_count} test cases",
            "updated_count": updated_count,
            "action": action
        }
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error in bulk update: {str(e)}"
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
    """Get historical failure rate data with real analysis."""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Build base query for test runs in the date range
        query = select(
            func.date(TestRun.started_at).label('run_date'),
            func.count(TestResult.id).label('total_tests'),
            func.sum(func.case((TestResult.status == 'failed', 1), else_=0)).label('failed_tests')
        ).select_from(
            TestRun.__table__.join(TestResult.__table__, TestRun.id == TestResult.run_id)
        ).where(
            and_(
                TestRun.started_at >= start_date,
                TestRun.started_at <= end_date
            )
        ).group_by(func.date(TestRun.started_at))
        
        # Apply suite filter if provided
        if suite_id:
            query = query.where(TestRun.suite_id == suite_id)
        
        result = await db.execute(query)
        daily_stats = result.fetchall()
        
        # Convert to response format and calculate failure rates
        trend_data = []
        for row in daily_stats:
            total_tests = row.total_tests or 0
            failed_tests = row.failed_tests or 0
            failure_rate = (failed_tests / total_tests) if total_tests > 0 else 0.0
            
            trend_data.append(FailureRateData(
                date=row.run_date,
                total_tests=total_tests,
                failed_tests=failed_tests,
                failure_rate=failure_rate
            ))
        
        # Fill in missing dates with zero data
        date_map = {item.date: item for item in trend_data}
        complete_data = []
        
        for i in range(days):
            current_date = (end_date - timedelta(days=i)).date()
            if current_date in date_map:
                complete_data.append(date_map[current_date])
            else:
                complete_data.append(FailureRateData(
                    date=current_date,
                    total_tests=0,
                    failed_tests=0,
                    failure_rate=0.0
                ))
        
        return sorted(complete_data, key=lambda x: x.date)
    
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
    """Get historical latency data with real analysis."""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Build base query for test results with latency data
        query = select(
            func.date(TestRun.started_at).label('run_date'),
            func.avg(TestResult.response_time_ms).label('avg_latency'),
            func.percentile_cont(0.95).within_group(TestResult.response_time_ms).label('p95_latency'),
            func.percentile_cont(0.99).within_group(TestResult.response_time_ms).label('p99_latency')
        ).select_from(
            TestRun.__table__.join(TestResult.__table__, TestRun.id == TestResult.run_id)
        ).where(
            and_(
                TestRun.started_at >= start_date,
                TestRun.started_at <= end_date,
                TestResult.response_time_ms.isnot(None)
            )
        ).group_by(func.date(TestRun.started_at))
        
        # Apply endpoint filter if provided
        if endpoint:
            query = query.where(TestResult.test_definition.contains(endpoint))
        
        result = await db.execute(query)
        daily_stats = result.fetchall()
        
        # Convert to response format
        trend_data = []
        for row in daily_stats:
            trend_data.append(LatencyData(
                date=row.run_date,
                avg_latency_ms=float(row.avg_latency or 0),
                p95_latency_ms=float(row.p95_latency or 0),
                p99_latency_ms=float(row.p99_latency or 0)
            ))
        
        # Fill in missing dates with zero data
        date_map = {item.date: item for item in trend_data}
        complete_data = []
        
        for i in range(days):
            current_date = (end_date - timedelta(days=i)).date()
            if current_date in date_map:
                complete_data.append(date_map[current_date])
            else:
                complete_data.append(LatencyData(
                    date=current_date,
                    avg_latency_ms=0.0,
                    p95_latency_ms=0.0,
                    p99_latency_ms=0.0
                ))
        
        return sorted(complete_data, key=lambda x: x.date)
    
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

# Advanced Analytics endpoints
@app.get("/api/v1/analytics/anomalies")
async def detect_anomalies(
    days: int = Query(30, description="Number of days to analyze"),
    threshold: float = Query(2.0, description="Standard deviation threshold for anomaly detection"),
    db: AsyncSession = Depends(get_db)
):
    """Detect anomalies in test performance and failure patterns."""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get daily failure rates and latencies
        query = select(
            func.date(TestRun.started_at).label('run_date'),
            func.count(TestResult.id).label('total_tests'),
            func.sum(func.case((TestResult.status == 'failed', 1), else_=0)).label('failed_tests'),
            func.avg(TestResult.response_time_ms).label('avg_latency')
        ).select_from(
            TestRun.__table__.join(TestResult.__table__, TestRun.id == TestResult.run_id)
        ).where(
            and_(
                TestRun.started_at >= start_date,
                TestRun.started_at <= end_date
            )
        ).group_by(func.date(TestRun.started_at))
        
        result = await db.execute(query)
        daily_stats = result.fetchall()
        
        if len(daily_stats) < 7:  # Need at least a week of data
            return {
                "anomalies": [],
                "message": "Insufficient data for anomaly detection (minimum 7 days required)"
            }
        
        # Calculate statistics for anomaly detection
        failure_rates = []
        latencies = []
        
        for row in daily_stats:
            total_tests = row.total_tests or 0
            failed_tests = row.failed_tests or 0
            failure_rate = (failed_tests / total_tests) if total_tests > 0 else 0.0
            failure_rates.append(failure_rate)
            latencies.append(float(row.avg_latency or 0))
        
        # Simple anomaly detection using standard deviation
        import statistics
        
        anomalies = []
        
        if len(failure_rates) > 1:
            failure_mean = statistics.mean(failure_rates)
            failure_stdev = statistics.stdev(failure_rates) if len(failure_rates) > 1 else 0
            
            for i, (row, rate) in enumerate(zip(daily_stats, failure_rates)):
                if failure_stdev > 0 and abs(rate - failure_mean) > threshold * failure_stdev:
                    anomalies.append({
                        "date": row.run_date.isoformat(),
                        "type": "failure_rate",
                        "value": rate,
                        "expected_range": [
                            max(0, failure_mean - threshold * failure_stdev),
                            min(1, failure_mean + threshold * failure_stdev)
                        ],
                        "severity": "high" if abs(rate - failure_mean) > 3 * failure_stdev else "medium"
                    })
        
        if len(latencies) > 1:
            latency_mean = statistics.mean(latencies)
            latency_stdev = statistics.stdev(latencies) if len(latencies) > 1 else 0
            
            for i, (row, latency) in enumerate(zip(daily_stats, latencies)):
                if latency_stdev > 0 and abs(latency - latency_mean) > threshold * latency_stdev:
                    anomalies.append({
                        "date": row.run_date.isoformat(),
                        "type": "latency",
                        "value": latency,
                        "expected_range": [
                            max(0, latency_mean - threshold * latency_stdev),
                            latency_mean + threshold * latency_stdev
                        ],
                        "severity": "high" if abs(latency - latency_mean) > 3 * latency_stdev else "medium"
                    })
        
        return {
            "anomalies": sorted(anomalies, key=lambda x: x["date"], reverse=True),
            "analysis_period": {
                "start_date": start_date.date().isoformat(),
                "end_date": end_date.date().isoformat(),
                "days_analyzed": len(daily_stats)
            },
            "baseline_metrics": {
                "avg_failure_rate": statistics.mean(failure_rates) if failure_rates else 0,
                "avg_latency_ms": statistics.mean(latencies) if latencies else 0
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error detecting anomalies: {str(e)}"
        )

@app.get("/api/v1/analytics/predictions")
async def get_quality_predictions(
    days_ahead: int = Query(7, description="Number of days to predict ahead"),
    db: AsyncSession = Depends(get_db)
):
    """Generate predictive quality insights based on historical trends."""
    try:
        # Get last 30 days of data for trend analysis
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        query = select(
            func.date(TestRun.started_at).label('run_date'),
            func.count(TestResult.id).label('total_tests'),
            func.sum(func.case((TestResult.status == 'failed', 1), else_=0)).label('failed_tests'),
            func.avg(TestResult.response_time_ms).label('avg_latency')
        ).select_from(
            TestRun.__table__.join(TestResult.__table__, TestRun.id == TestResult.run_id)
        ).where(
            and_(
                TestRun.started_at >= start_date,
                TestRun.started_at <= end_date
            )
        ).group_by(func.date(TestRun.started_at)).order_by(func.date(TestRun.started_at))
        
        result = await db.execute(query)
        daily_stats = result.fetchall()
        
        if len(daily_stats) < 7:
            return {
                "predictions": [],
                "message": "Insufficient historical data for predictions (minimum 7 days required)"
            }
        
        # Simple linear trend analysis
        failure_rates = []
        latencies = []
        days = []
        
        for i, row in enumerate(daily_stats):
            total_tests = row.total_tests or 0
            failed_tests = row.failed_tests or 0
            failure_rate = (failed_tests / total_tests) if total_tests > 0 else 0.0
            failure_rates.append(failure_rate)
            latencies.append(float(row.avg_latency or 0))
            days.append(i)
        
        predictions = []
        
        # Simple linear regression for trend prediction
        if len(failure_rates) >= 2:
            # Calculate trend for failure rate
            n = len(failure_rates)
            sum_x = sum(days)
            sum_y = sum(failure_rates)
            sum_xy = sum(x * y for x, y in zip(days, failure_rates))
            sum_x2 = sum(x * x for x in days)
            
            if n * sum_x2 - sum_x * sum_x != 0:
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                intercept = (sum_y - slope * sum_x) / n
                
                for i in range(1, days_ahead + 1):
                    future_day = len(days) + i
                    predicted_failure_rate = max(0, min(1, slope * future_day + intercept))
                    
                    predictions.append({
                        "date": (end_date + timedelta(days=i)).date().isoformat(),
                        "predicted_failure_rate": predicted_failure_rate,
                        "trend": "improving" if slope < -0.01 else "degrading" if slope > 0.01 else "stable",
                        "confidence": "medium" if abs(slope) < 0.05 else "low"
                    })
        
        # Generate recommendations based on trends
        recommendations = []
        if predictions:
            avg_predicted_failure = sum(p["predicted_failure_rate"] for p in predictions) / len(predictions)
            current_failure = failure_rates[-1] if failure_rates else 0
            
            if avg_predicted_failure > current_failure * 1.2:
                recommendations.append("Quality degradation predicted - consider increasing test coverage")
            elif avg_predicted_failure < current_failure * 0.8:
                recommendations.append("Quality improvement trend detected - maintain current practices")
            
            if avg_predicted_failure > 0.3:
                recommendations.append("High failure rate predicted - review recent code changes")
        
        return {
            "predictions": predictions,
            "recommendations": recommendations,
            "analysis_period": {
                "historical_days": len(daily_stats),
                "prediction_days": days_ahead
            },
            "current_metrics": {
                "failure_rate": failure_rates[-1] if failure_rates else 0,
                "avg_latency_ms": latencies[-1] if latencies else 0
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating predictions: {str(e)}"
        )

@app.get("/api/v1/analytics/insights")
async def get_quality_insights(
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db)
):
    """Generate comprehensive quality insights and recommendations."""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get comprehensive test data
        query = select(
            TestResult.agent_type,
            TestResult.status,
            TestResult.response_time_ms,
            func.count(TestResult.id).label('count')
        ).select_from(
            TestRun.__table__.join(TestResult.__table__, TestRun.id == TestResult.run_id)
        ).where(
            and_(
                TestRun.started_at >= start_date,
                TestRun.started_at <= end_date
            )
        ).group_by(TestResult.agent_type, TestResult.status)
        
        result = await db.execute(query)
        agent_stats = result.fetchall()
        
        # Analyze by agent type
        agent_insights = {}
        total_tests = 0
        total_failures = 0
        
        for row in agent_stats:
            agent_type = row.agent_type
            status = row.status
            count = row.count
            
            if agent_type not in agent_insights:
                agent_insights[agent_type] = {
                    "total_tests": 0,
                    "failed_tests": 0,
                    "passed_tests": 0,
                    "error_tests": 0
                }
            
            agent_insights[agent_type]["total_tests"] += count
            total_tests += count
            
            if status == "failed":
                agent_insights[agent_type]["failed_tests"] += count
                total_failures += count
            elif status == "passed":
                agent_insights[agent_type]["passed_tests"] += count
            elif status == "error":
                agent_insights[agent_type]["error_tests"] += count
        
        # Calculate failure rates and generate insights
        insights = []
        recommendations = []
        
        for agent_type, stats in agent_insights.items():
            if stats["total_tests"] > 0:
                failure_rate = stats["failed_tests"] / stats["total_tests"]
                
                if failure_rate > 0.3:
                    insights.append({
                        "type": "high_failure_rate",
                        "agent_type": agent_type,
                        "failure_rate": failure_rate,
                        "severity": "high",
                        "message": f"{agent_type} has high failure rate ({failure_rate:.1%})"
                    })
                    recommendations.append(f"Review {agent_type} test cases and underlying API issues")
                
                elif failure_rate < 0.05:
                    insights.append({
                        "type": "excellent_quality",
                        "agent_type": agent_type,
                        "failure_rate": failure_rate,
                        "severity": "info",
                        "message": f"{agent_type} shows excellent quality ({failure_rate:.1%} failure rate)"
                    })
        
        # Overall quality assessment
        overall_failure_rate = total_failures / total_tests if total_tests > 0 else 0
        quality_score = max(0, min(100, (1 - overall_failure_rate) * 100))
        
        quality_grade = "A" if quality_score >= 95 else "B" if quality_score >= 85 else "C" if quality_score >= 70 else "D" if quality_score >= 60 else "F"
        
        return {
            "overall_quality": {
                "score": quality_score,
                "grade": quality_grade,
                "failure_rate": overall_failure_rate,
                "total_tests": total_tests
            },
            "agent_performance": [
                {
                    "agent_type": agent_type,
                    "total_tests": stats["total_tests"],
                    "failure_rate": stats["failed_tests"] / stats["total_tests"] if stats["total_tests"] > 0 else 0,
                    "success_rate": stats["passed_tests"] / stats["total_tests"] if stats["total_tests"] > 0 else 0
                }
                for agent_type, stats in agent_insights.items()
            ],
            "insights": insights,
            "recommendations": recommendations,
            "analysis_period": {
                "start_date": start_date.date().isoformat(),
                "end_date": end_date.date().isoformat(),
                "days_analyzed": days
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating quality insights: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "data-analytics-service"}
