from sqlalchemy import Column, Integer, String, Text, Float, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ApiSpecification(Base):
    __tablename__ = "api_specifications"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, nullable=True)  # Optional foreign key for future use
    title = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    raw_spec = Column(Text, nullable=False)
    parsed_spec = Column(JSONB, nullable=False)
    internal_graph = Column(JSONB, nullable=True)
    source_url = Column(Text, nullable=True)
    source_filename = Column(Text, nullable=True)
    llm_readiness_score = Column(Float, nullable=True)
    version = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
