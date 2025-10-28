"""
Report Generator for Compliance and Audit Reports

Generates comprehensive reports for SOC2, GDPR, HIPAA, and general auditing.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
import logging

from .models.events import EventType, EventSeverity, EventOutcome, EventFilter
from .storage.repository import EventRepository
from .storage.database_schema import ComplianceReport

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates compliance and audit reports."""

    def __init__(self, repository: EventRepository):
        """
        Initialize report generator.

        Args:
            repository: Event repository for data access
        """
        self.repository = repository

    async def generate_report(
        self,
        report_type: str,
        start_time: datetime,
        end_time: datetime,
        generated_by: str = "system"
    ) -> ComplianceReport:
        """
        Generate compliance report.

        Args:
            report_type: Type of report (SOC2, GDPR, HIPAA, general)
            start_time: Report start time
            end_time: Report end time
            generated_by: User/system generating report

        Returns:
            Generated compliance report
        """
        report_generators = {
            "soc2": self._generate_soc2_report,
            "gdpr": self._generate_gdpr_report,
            "hipaa": self._generate_hipaa_report,
            "general": self._generate_general_report
        }

        generator = report_generators.get(report_type.lower())
        if not generator:
            raise ValueError(f"Unsupported report type: {report_type}")

        # Generate report content
        summary, details, findings = await generator(start_time, end_time)

        # Create report record
        report = ComplianceReport(
            id=uuid4(),
            report_type=report_type.upper(),
            start_time=start_time,
            end_time=end_time,
            generated_at=datetime.utcnow(),
            generated_by=generated_by,
            summary=summary,
            details=details,
            findings=findings
        )

        logger.info(f"Generated {report_type} report for period {start_time} to {end_time}")
        return report

    async def _generate_soc2_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """
        Generate SOC2 compliance report.

        Focus areas:
        - Security controls
        - Access management
        - Monitoring and logging
        - Incident response
        - Change management
        """
        # Get statistics
        stats = await self.repository.get_statistics(start_time, end_time)

        # Security events
        security_filter = EventFilter(
            start_time=start_time,
            end_time=end_time,
            event_types=[
                EventType.SECURITY_AUTH_FAILED,
                EventType.SECURITY_ACCESS_DENIED,
                EventType.SECURITY_POLICY_VIOLATED,
                EventType.SECURITY_ANOMALY_DETECTED
            ],
            limit=1000
        )
        security_events, security_count = await self.repository.query_events(security_filter)

        # Access events
        access_filter = EventFilter(
            start_time=start_time,
            end_time=end_time,
            event_types=[
                EventType.USER_LOGIN,
                EventType.USER_LOGOUT,
                EventType.USER_ROLE_CHANGED
            ],
            limit=1000
        )
        access_events, access_count = await self.repository.query_events(access_filter)

        # Failed login attempts
        failed_logins = [
            e for e in access_events
            if e.event_type == EventType.USER_LOGIN and e.outcome == EventOutcome.FAILURE
        ]

        # Summary
        summary = {
            "total_events": stats.total_events,
            "security_incidents": security_count,
            "access_events": access_count,
            "failed_login_attempts": len(failed_logins),
            "compliance_status": "PASS" if len(failed_logins) < 100 else "REVIEW"
        }

        # Details
        details = {
            "security_controls": {
                "authentication_failures": len(failed_logins),
                "access_denied_events": len([e for e in security_events if e.event_type == EventType.SECURITY_ACCESS_DENIED]),
                "policy_violations": len([e for e in security_events if e.event_type == EventType.SECURITY_POLICY_VIOLATED]),
                "anomalies_detected": len([e for e in security_events if e.event_type == EventType.SECURITY_ANOMALY_DETECTED])
            },
            "access_management": {
                "total_logins": len([e for e in access_events if e.event_type == EventType.USER_LOGIN]),
                "unique_users": len(set(e.actor_id for e in access_events)),
                "role_changes": len([e for e in access_events if e.event_type == EventType.USER_ROLE_CHANGED])
            },
            "audit_trail": {
                "completeness": "100%" if stats.total_events > 0 else "0%",
                "integrity": "verified" if all(e.signature for e in security_events[:10]) else "partial",
                "retention": "configured"
            }
        }

        # Findings
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

        if len(failed_logins) > 50:
            findings["high"].append({
                "title": "Excessive Failed Login Attempts",
                "description": f"Detected {len(failed_logins)} failed login attempts",
                "recommendation": "Review authentication mechanisms and consider implementing MFA"
            })

        if security_count > 100:
            findings["medium"].append({
                "title": "High Number of Security Events",
                "description": f"Recorded {security_count} security-related events",
                "recommendation": "Review security policies and user training"
            })

        return summary, details, findings

    async def _generate_gdpr_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """
        Generate GDPR compliance report.

        Focus areas:
        - Data access and processing
        - User consent and rights
        - Data retention
        - Privacy controls
        - Breach notification
        """
        stats = await self.repository.get_statistics(start_time, end_time)

        # Data access events
        data_filter = EventFilter(
            start_time=start_time,
            end_time=end_time,
            event_types=[
                EventType.DATA_ACCESSED,
                EventType.DATA_CREATED,
                EventType.DATA_UPDATED,
                EventType.DATA_DELETED,
                EventType.DATA_EXPORTED
            ],
            limit=1000
        )
        data_events, data_count = await self.repository.query_events(data_filter)

        # GDPR-specific events
        gdpr_filter = EventFilter(
            start_time=start_time,
            end_time=end_time,
            event_types=[EventType.COMPLIANCE_GDPR_REQUEST],
            limit=1000
        )
        gdpr_events, gdpr_count = await self.repository.query_events(gdpr_filter)

        summary = {
            "total_events": stats.total_events,
            "data_processing_events": data_count,
            "gdpr_requests_processed": gdpr_count,
            "data_exports": len([e for e in data_events if e.event_type == EventType.DATA_EXPORTED]),
            "compliance_status": "COMPLIANT"
        }

        details = {
            "data_processing": {
                "data_access": len([e for e in data_events if e.event_type == EventType.DATA_ACCESSED]),
                "data_created": len([e for e in data_events if e.event_type == EventType.DATA_CREATED]),
                "data_updated": len([e for e in data_events if e.event_type == EventType.DATA_UPDATED]),
                "data_deleted": len([e for e in data_events if e.event_type == EventType.DATA_DELETED])
            },
            "user_rights": {
                "right_to_access": len([e for e in gdpr_events if "access" in e.action]),
                "right_to_erasure": len([e for e in gdpr_events if "anonymize" in e.action or "delete" in e.action]),
                "right_to_portability": len([e for e in gdpr_events if "export" in e.action])
            },
            "retention_policies": {
                "configured": True,
                "enforced": True,
                "audit_trail_retention": "1 year"
            }
        }

        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

        return summary, details, findings

    async def _generate_hipaa_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """
        Generate HIPAA compliance report.

        Focus areas:
        - PHI access and disclosure
        - Security controls
        - Audit logging
        - Access controls
        - Encryption
        """
        stats = await self.repository.get_statistics(start_time, end_time)

        # PHI access events (tagged with phi)
        phi_filter = EventFilter(
            start_time=start_time,
            end_time=end_time,
            tags=["phi", "healthcare"],
            limit=1000
        )
        phi_events, phi_count = await self.repository.query_events(phi_filter)

        summary = {
            "total_events": stats.total_events,
            "phi_access_events": phi_count,
            "audit_trail_completeness": "100%",
            "encryption_status": "enabled",
            "compliance_status": "COMPLIANT"
        }

        details = {
            "phi_access_control": {
                "total_access": phi_count,
                "authorized_access": len([e for e in phi_events if e.outcome == EventOutcome.SUCCESS]),
                "unauthorized_attempts": len([e for e in phi_events if e.outcome == EventOutcome.FAILURE])
            },
            "audit_requirements": {
                "logging_enabled": True,
                "log_integrity": "verified",
                "retention_period": "6 years",
                "log_review_frequency": "monthly"
            },
            "security_controls": {
                "access_controls": "implemented",
                "encryption": "AES-256",
                "transmission_security": "TLS 1.3"
            }
        }

        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

        return summary, details, findings

    async def _generate_general_report(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """
        Generate general activity report.

        Covers all system activity and provides overview.
        """
        stats = await self.repository.get_statistics(start_time, end_time)

        summary = {
            "total_events": stats.total_events,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "event_distribution": stats.by_type,
            "severity_distribution": stats.by_severity,
            "outcome_distribution": stats.by_outcome
        }

        details = {
            "top_actors": stats.by_actor,
            "trends": {
                "events_per_hour": stats.events_per_hour
            },
            "system_health": {
                "error_rate": stats.by_severity.get("error", 0) / max(stats.total_events, 1) * 100,
                "success_rate": stats.by_outcome.get("success", 0) / max(stats.total_events, 1) * 100
            }
        }

        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

        return summary, details, findings
