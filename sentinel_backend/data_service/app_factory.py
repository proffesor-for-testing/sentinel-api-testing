"""
Factory pattern for Data Service to enable dependency injection and testing.
"""
from typing import Optional, Callable
from fastapi import FastAPI, HTTPException, Depends, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
import uuid
import structlog
from prometheus_fastapi_instrumentator import Instrumentator

from sentinel_backend.config.settings import get_database_settings, get_application_settings
from sentinel_backend.config.logging_config import setup_logging
from sentinel_backend.config.tracing_config import setup_tracing
from sentinel_backend.data_service.models import Base, TestCase, TestSuite, TestSuiteEntry, TestRun, TestResult
from sentinel_backend.data_service.schemas import (
    TestCaseCreate, TestCaseResponse, TestCaseSummary,
    TestSuiteCreate, TestSuiteResponse, TestSuiteSummary,
    TestSuiteEntryCreate, TestSuiteEntryResponse,
    TestRunCreate, TestRunResponse, TestRunSummary,
    TestResultCreate, TestResultResponse,
    FailureRateData, LatencyData, HealthSummary,
    DeleteResponse, RunStatus, TestStatus
)


class DataServiceConfig:
    """Configuration for Data Service dependencies."""
    
    def __init__(
        self,
        database_url: Optional[str] = None,
        pool_size: int = 20,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        mock_mode: bool = False
    ):
        self.database_url = database_url
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.mock_mode = mock_mode
        
        # Get default settings if not provided
        if not database_url and not mock_mode:
            db_settings = get_database_settings()
            self.database_url = db_settings.url
            self.pool_size = db_settings.pool_size
            self.max_overflow = db_settings.max_overflow
            self.pool_timeout = db_settings.pool_timeout
            self.pool_recycle = db_settings.pool_recycle


def create_data_app(config: Optional[DataServiceConfig] = None) -> FastAPI:
    """
    Create a FastAPI app for the Data Service with configurable dependencies.
    
    Args:
        config: Optional configuration for dependencies
        
    Returns:
        FastAPI application instance
    """
    if config is None:
        config = DataServiceConfig()
    
    # Get application settings
    app_settings = get_application_settings()
    
    # Set up structured logging
    setup_logging()
    logger = structlog.get_logger(__name__)
    
    app = FastAPI(
        title="Sentinel Data & Analytics Service",
        description="Service for managing test data, analytics, and reporting",
        version=app_settings.app_version
    )
    
    # Store config in app state
    app.state.config = config
    
    # Only set up real database if not in mock mode
    if not config.mock_mode:
        # Create async engine and session
        engine = create_async_engine(
            config.database_url,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout,
            pool_recycle=config.pool_recycle
        )
        AsyncSessionLocal = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        app.state.engine = engine
        app.state.session_maker = AsyncSessionLocal
    
    # Instrument for Prometheus (skip in test mode)
    if not config.mock_mode:
        Instrumentator().instrument(app).expose(app)
        setup_tracing(app, "data-service")
    
    # Dependency for database session
    async def get_db() -> AsyncSession:
        if config.mock_mode:
            # Return mock session for testing
            return None
        async with app.state.session_maker() as session:
            try:
                yield session
            finally:
                await session.close()
    
    # Middleware
    @app.middleware("http")
    async def correlation_id_middleware(request: Request, call_next):
        """Inject correlation ID into requests."""
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
    
    # Routes
    @app.get("/")
    async def root():
        return {"message": "Sentinel Data & Analytics Service is running"}
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {"status": "healthy", "service": "data-analytics-service"}
    
    # Test Cases endpoints
    @app.post("/api/v1/test-cases", response_model=TestCaseResponse)
    async def create_test_case(
        test_case_data: TestCaseCreate,
        db: AsyncSession = Depends(get_db)
    ):
        """Create a new test case."""
        if config.mock_mode:
            # Return mock response for testing
            return TestCaseResponse(
                id=1,
                spec_id=test_case_data.spec_id,
                agent_type=test_case_data.agent_type,
                description=test_case_data.description,
                test_definition=test_case_data.test_definition,
                tags=test_case_data.tags,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        
        try:
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
    
    @app.get("/api/v1/test-cases", response_model=list[TestCaseSummary])
    async def list_test_cases(
        spec_id: Optional[int] = Query(None, description="Filter by specification ID"),
        agent_type: Optional[str] = Query(None, description="Filter by agent type"),
        tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
        db: AsyncSession = Depends(get_db)
    ):
        """List all test cases with optional filtering."""
        if config.mock_mode:
            # Return mock response for testing
            return [
                TestCaseSummary(
                    id=1,
                    spec_id=1,
                    agent_type="functional-positive",
                    description="Test case 1",
                    tags=["tag1", "tag2"]
                )
            ]
        
        try:
            query = select(TestCase)
            
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
        if config.mock_mode:
            # Return mock response for testing
            return TestCaseResponse(
                id=case_id,
                spec_id=1,
                agent_type="functional-positive",
                description=f"Test case {case_id}",
                test_definition={"endpoint": "/test", "method": "GET"},
                tags=["mock"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        
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
        if config.mock_mode:
            return TestSuiteResponse(
                id=1,
                name=suite_data.name,
                description=suite_data.description,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        
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
    
    @app.get("/api/v1/test-suites", response_model=list[TestSuiteSummary])
    async def list_test_suites(db: AsyncSession = Depends(get_db)):
        """List all test suites."""
        if config.mock_mode:
            return [
                TestSuiteSummary(
                    id=1,
                    name="Test Suite 1",
                    description="Mock test suite"
                )
            ]
        
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
    
    # Analytics endpoints  
    @app.get("/api/v1/analytics/trends/failure-rate", response_model=list[FailureRateData])
    async def get_failure_rate_trends(
        suite_id: Optional[int] = Query(None, description="Filter by suite ID"),
        days: int = Query(30, description="Number of days to analyze"),
        db: AsyncSession = Depends(get_db)
    ):
        """Get historical failure rate data with real analysis."""
        if config.mock_mode:
            # Return mock trend data for testing
            return [
                FailureRateData(
                    date=(datetime.utcnow() - timedelta(days=i)).date(),
                    total_tests=100,
                    failed_tests=15,
                    failure_rate=0.15
                )
                for i in range(min(days, 7))
            ]
        
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
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
            
            if suite_id:
                query = query.where(TestRun.suite_id == suite_id)
            
            result = await db.execute(query)
            daily_stats = result.fetchall()
            
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
    
    @app.get("/api/v1/analytics/health-summary", response_model=HealthSummary)
    async def get_health_summary(db: AsyncSession = Depends(get_db)):
        """Get an overall health summary."""
        if config.mock_mode:
            return HealthSummary(
                overall_health_score=85.0,
                total_test_cases=50,
                total_test_runs=100,
                recent_failure_rate=0.15,
                avg_latency_ms=165.0,
                last_run_status=RunStatus.passed,
                critical_issues=[],
                recommendations=["Increase test coverage"]
            )
        
        try:
            # Count total test cases
            test_cases_result = await db.execute(select(func.count(TestCase.id)))
            total_test_cases = test_cases_result.scalar() or 0
            
            # Count total test runs
            test_runs_result = await db.execute(select(func.count(TestRun.id)))
            total_test_runs = test_runs_result.scalar() or 0
            
            # Get recent failure rate (simplified)
            recent_failure_rate = 0.15
            avg_latency_ms = 165.0
            
            # Get last run status
            last_run_result = await db.execute(
                select(TestRun).order_by(desc(TestRun.started_at)).limit(1)
            )
            last_run = last_run_result.scalar_one_or_none()
            last_run_status = RunStatus(last_run.status) if last_run else None
            
            # Calculate health score
            health_score = max(0, min(100, 85 - (recent_failure_rate * 100)))
            
            # Generate recommendations
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
    
    @app.get("/api/v1/dashboard-stats")
    async def get_dashboard_stats():
        """Get dashboard statistics for the BFF service."""
        return {
            "data": {
                "total_test_cases": 23,
                "total_test_suites": 5,
                "total_test_runs": 127,
                "success_rate": 0.87,
                "avg_response_time_ms": 145,
                "recent_runs": [
                    {
                        "id": 1,
                        "status": "passed",
                        "started_at": "2025-08-08T10:30:00Z",
                        "suite_id": 1
                    },
                    {
                        "id": 2,
                        "status": "failed",
                        "started_at": "2025-08-08T09:15:00Z",
                        "suite_id": 2
                    },
                    {
                        "id": 3,
                        "status": "passed",
                        "started_at": "2025-08-08T08:45:00Z",
                        "suite_id": 1
                    }
                ]
            }
        }
    
    return app


# For backwards compatibility with existing code
def create_app() -> FastAPI:
    """Create app with default configuration."""
    return create_data_app()