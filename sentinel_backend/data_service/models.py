from sqlalchemy import Column, Integer, String, Text, BigInteger, DateTime, func, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class TestCase(Base):
    __tablename__ = "test_cases"
    
    id = Column(Integer, primary_key=True, index=True)
    spec_id = Column(Integer, nullable=False)  # Removed FK to avoid cross-service dependency
    agent_type = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    test_definition = Column(JSONB, nullable=False)
    tags = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    suite_entries = relationship("TestSuiteEntry", back_populates="test_case")
    test_results = relationship("TestResult", back_populates="test_case")

class TestSuite(Base):
    __tablename__ = "test_suites"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships with proper cascade deletion
    suite_entries = relationship("TestSuiteEntry", back_populates="test_suite", cascade="all, delete-orphan")
    test_runs = relationship("TestRun", back_populates="test_suite", cascade="all, delete-orphan")

class TestSuiteEntry(Base):
    __tablename__ = "test_suite_entries"
    
    suite_id = Column(Integer, ForeignKey("test_suites.id"), primary_key=True)
    case_id = Column(Integer, ForeignKey("test_cases.id"), primary_key=True)
    execution_order = Column(Integer, default=0)
    
    # Relationships
    test_suite = relationship("TestSuite", back_populates="suite_entries")
    test_case = relationship("TestCase", back_populates="suite_entries")

class TestRun(Base):
    __tablename__ = "test_runs"
    
    id = Column(Integer, primary_key=True, index=True)
    suite_id = Column(Integer, ForeignKey("test_suites.id"), nullable=False)
    status = Column(String(50), nullable=False)
    target_environment = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    test_suite = relationship("TestSuite", back_populates="test_runs")
    test_results = relationship("TestResult", back_populates="test_run")

class TestResult(Base):
    __tablename__ = "test_results"
    
    id = Column(BigInteger, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("test_runs.id"), nullable=False)
    case_id = Column(Integer, ForeignKey("test_cases.id"), nullable=False)
    status = Column(String(50), nullable=False)
    response_code = Column(Integer, nullable=True)
    response_headers = Column(JSONB, nullable=True)
    response_body = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    assertion_failures = Column(JSONB, nullable=True)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    test_run = relationship("TestRun", back_populates="test_results")
    test_case = relationship("TestCase", back_populates="test_results")
