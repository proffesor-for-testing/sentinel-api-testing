"""
Audit Service REST API

Provides endpoints for querying audit events, generating reports, and managing compliance.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
import csv
import json
import io
import logging

from .models.events import (
    EventFilter, EventStatistics, EventType,
    EventSeverity, EventOutcome, AuditEvent
)
from .storage.repository import EventRepository
from .reports import ReportGenerator
from .emitter import EventEmitter, get_global_emitter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


# Dependency injection
async def get_repository() -> EventRepository:
    """Get event repository instance."""
    from ..config.settings import get_database_settings
    db_settings = get_database_settings()
    repo = EventRepository(db_settings.url)
    await repo.initialize()
    return repo


@router.get("/events", summary="Query audit events")
async def query_events(
    start_time: Optional[datetime] = Query(None, description="Start time (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time (UTC)"),
    event_types: Optional[List[EventType]] = Query(None, description="Event types"),
    severities: Optional[List[EventSeverity]] = Query(None, description="Severities"),
    outcomes: Optional[List[EventOutcome]] = Query(None, description="Outcomes"),
    actor_ids: Optional[List[str]] = Query(None, description="Actor IDs"),
    resource_ids: Optional[List[str]] = Query(None, description="Resource IDs"),
    search: Optional[str] = Query(None, description="Search query"),
    tags: Optional[List[str]] = Query(None, description="Tags"),
    limit: int = Query(100, ge=1, le=1000, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    repo: EventRepository = Depends(get_repository)
):
    """
    Query audit events with filtering and pagination.

    Supports:
    - Time range filtering
    - Event type, severity, outcome filtering
    - Actor and resource filtering
    - Full-text search
    - Tag-based filtering
    """
    try:
        # Build filter
        event_filter = EventFilter(
            start_time=start_time or datetime.utcnow() - timedelta(days=7),
            end_time=end_time or datetime.utcnow(),
            event_types=event_types,
            severities=severities,
            outcomes=outcomes,
            actor_ids=actor_ids,
            resource_ids=resource_ids,
            search_query=search,
            tags=tags,
            limit=limit,
            offset=offset
        )

        # Query events
        events, total = await repo.query_events(event_filter)

        return {
            "events": [event.to_dict() for event in events],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(events) < total
        }

    except Exception as e:
        logger.error(f"Error querying events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/events/{event_id}", summary="Get event by ID")
async def get_event(
    event_id: UUID,
    repo: EventRepository = Depends(get_repository)
):
    """Get specific audit event by ID."""
    try:
        event = await repo.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        return event.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", summary="Get event statistics")
async def get_statistics(
    start_time: Optional[datetime] = Query(None, description="Start time (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time (UTC)"),
    repo: EventRepository = Depends(get_repository)
):
    """
    Get statistical summary of events for time range.

    Returns:
    - Total event count
    - Breakdown by type, severity, outcome
    - Top actors and resources
    - Time-series trends
    """
    try:
        stats = await repo.get_statistics(
            start_time=start_time or datetime.utcnow() - timedelta(days=7),
            end_time=end_time or datetime.utcnow()
        )

        return stats.dict()

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/export", summary="Export audit events")
async def export_events(
    format: str = Query("csv", regex="^(csv|json)$", description="Export format"),
    start_time: Optional[datetime] = Query(None, description="Start time (UTC)"),
    end_time: Optional[datetime] = Query(None, description="End time (UTC)"),
    event_types: Optional[List[EventType]] = Query(None, description="Event types"),
    repo: EventRepository = Depends(get_repository)
):
    """
    Export audit events in CSV or JSON format.

    Supports filtering by time range and event types.
    """
    try:
        # Build filter
        event_filter = EventFilter(
            start_time=start_time or datetime.utcnow() - timedelta(days=30),
            end_time=end_time or datetime.utcnow(),
            event_types=event_types,
            limit=10000  # Maximum export size
        )

        # Query events
        events, _ = await repo.query_events(event_filter)

        if format == "csv":
            # Generate CSV
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                'id', 'timestamp', 'event_type', 'severity', 'outcome',
                'actor_id', 'actor_type', 'action', 'resource_id', 'description'
            ])
            writer.writeheader()

            for event in events:
                writer.writerow({
                    'id': str(event.id),
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'outcome': event.outcome.value,
                    'actor_id': event.actor_id,
                    'actor_type': event.actor_type,
                    'action': event.action,
                    'resource_id': event.resource_id or '',
                    'description': event.description or ''
                })

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=audit_events_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
            )

        else:  # JSON
            events_data = [event.to_dict() for event in events]
            return StreamingResponse(
                iter([json.dumps(events_data, indent=2)]),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=audit_events_{datetime.utcnow().strftime('%Y%m%d')}.json"}
            )

    except Exception as e:
        logger.error(f"Error exporting events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reports/generate", summary="Generate compliance report")
async def generate_report(
    report_type: str = Query(..., description="Report type (SOC2, GDPR, HIPAA, general)"),
    start_time: datetime = Query(..., description="Start time (UTC)"),
    end_time: datetime = Query(..., description="End time (UTC)"),
    background_tasks: BackgroundTasks = None,
    repo: EventRepository = Depends(get_repository)
):
    """
    Generate compliance report for specified time range.

    Supported report types:
    - SOC2: Security and compliance controls
    - GDPR: Data protection and privacy
    - HIPAA: Healthcare data security
    - general: General activity report
    """
    try:
        generator = ReportGenerator(repo)

        # Generate report
        report = await generator.generate_report(
            report_type=report_type,
            start_time=start_time,
            end_time=end_time
        )

        return {
            "report_id": str(report.id),
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "summary": report.summary,
            "details": report.details
        }

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compliance/anonymize", summary="Anonymize user events (GDPR)")
async def anonymize_user_events(
    user_id: str = Query(..., description="User ID to anonymize"),
    repo: EventRepository = Depends(get_repository),
    emitter: EventEmitter = Depends(get_global_emitter)
):
    """
    Anonymize all events for a user (GDPR right to be forgotten).

    This operation:
    - Removes personal identifiable information
    - Preserves statistical data
    - Is irreversible
    """
    try:
        count = await repo.anonymize_user_events(user_id)

        # Emit compliance event
        await emitter.emit(
            event_type=EventType.COMPLIANCE_GDPR_REQUEST,
            actor={"id": "system", "type": "system"},
            action="anonymize_user_events",
            outcome=EventOutcome.SUCCESS,
            metadata={"user_id": user_id, "events_anonymized": count},
            tags=["gdpr", "compliance"]
        )

        return {
            "success": True,
            "user_id": user_id,
            "events_anonymized": count
        }

    except Exception as e:
        logger.error(f"Error anonymizing user events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health", summary="Health check")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "audit",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/metrics", summary="Service metrics")
async def get_metrics(
    emitter: EventEmitter = Depends(get_global_emitter)
):
    """Get audit service metrics."""
    stats = emitter.get_statistics()

    return {
        "metrics": stats,
        "timestamp": datetime.utcnow().isoformat()
    }
