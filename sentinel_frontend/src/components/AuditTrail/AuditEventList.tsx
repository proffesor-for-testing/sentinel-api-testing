import React, { useState, useEffect } from 'react';
import { format } from 'date-fns';
import './AuditEventList.css';

interface EventActor {
  id: string;
  type: string;
  name?: string;
  ip_address?: string;
}

interface EventResource {
  id: string;
  type: string;
  name?: string;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  outcome: string;
  actor: EventActor;
  action: string;
  resource?: EventResource;
  description?: string;
  duration_ms?: number;
  tags: string[];
}

interface AuditEventListProps {
  startTime?: Date;
  endTime?: Date;
  eventTypes?: string[];
  searchQuery?: string;
}

const AuditEventList: React.FC<AuditEventListProps> = ({
  startTime,
  endTime,
  eventTypes,
  searchQuery
}) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize] = useState(50);

  useEffect(() => {
    fetchEvents();
  }, [startTime, endTime, eventTypes, searchQuery, page]);

  const fetchEvents = async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams({
        limit: pageSize.toString(),
        offset: (page * pageSize).toString()
      });

      if (startTime) params.append('start_time', startTime.toISOString());
      if (endTime) params.append('end_time', endTime.toISOString());
      if (eventTypes?.length) {
        eventTypes.forEach(type => params.append('event_types', type));
      }
      if (searchQuery) params.append('search', searchQuery);

      const response = await fetch(`/api/v1/audit/events?${params}`);
      if (!response.ok) throw new Error('Failed to fetch events');

      const data = await response.json();
      setEvents(data.events);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      debug: '#6b7280',
      info: '#3b82f6',
      warning: '#f59e0b',
      error: '#ef4444',
      critical: '#dc2626'
    };
    return colors[severity.toLowerCase()] || '#6b7280';
  };

  const getOutcomeIcon = (outcome: string) => {
    const icons: Record<string, string> = {
      success: '✓',
      failure: '✗',
      partial: '⚠',
      pending: '⏳',
      cancelled: '⊘'
    };
    return icons[outcome.toLowerCase()] || '?';
  };

  const exportEvents = async (format: 'csv' | 'json') => {
    try {
      const params = new URLSearchParams({ format });
      if (startTime) params.append('start_time', startTime.toISOString());
      if (endTime) params.append('end_time', endTime.toISOString());

      const response = await fetch(`/api/v1/audit/export?${params}`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_events_${format}_${Date.now()}.${format}`;
      a.click();
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  return (
    <div className="audit-event-list">
      <div className="audit-header">
        <h2>Audit Trail</h2>
        <div className="audit-actions">
          <button onClick={() => exportEvents('csv')} className="btn-secondary">
            Export CSV
          </button>
          <button onClick={() => exportEvents('json')} className="btn-secondary">
            Export JSON
          </button>
          <button onClick={fetchEvents} className="btn-primary">
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-error">
          <strong>Error:</strong> {error}
        </div>
      )}

      <div className="audit-stats">
        <span className="stat">
          Total Events: <strong>{total.toLocaleString()}</strong>
        </span>
        <span className="stat">
          Showing: <strong>{events.length}</strong> of <strong>{total}</strong>
        </span>
      </div>

      {loading ? (
        <div className="loading-spinner">Loading events...</div>
      ) : (
        <>
          <div className="event-table-container">
            <table className="event-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Type</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Outcome</th>
                  <th>Severity</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className={`severity-${event.severity.toLowerCase()}`}>
                    <td className="timestamp">
                      {format(new Date(event.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                    </td>
                    <td className="event-type">
                      <span className="badge">{event.event_type}</span>
                    </td>
                    <td className="actor">
                      <div className="actor-info">
                        <span className="actor-name">{event.actor.name || event.actor.id}</span>
                        {event.actor.ip_address && (
                          <span className="actor-ip">{event.actor.ip_address}</span>
                        )}
                      </div>
                    </td>
                    <td className="action">{event.action}</td>
                    <td className="resource">
                      {event.resource && (
                        <span className="resource-name">
                          {event.resource.name || event.resource.id}
                        </span>
                      )}
                    </td>
                    <td className="outcome">
                      <span className={`outcome-badge outcome-${event.outcome.toLowerCase()}`}>
                        {getOutcomeIcon(event.outcome)} {event.outcome}
                      </span>
                    </td>
                    <td className="severity">
                      <span
                        className="severity-indicator"
                        style={{ backgroundColor: getSeverityColor(event.severity) }}
                      >
                        {event.severity}
                      </span>
                    </td>
                    <td className="duration">
                      {event.duration_ms !== undefined ? `${event.duration_ms}ms` : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {total > pageSize && (
            <div className="pagination">
              <button
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="btn-secondary"
              >
                Previous
              </button>
              <span className="page-info">
                Page {page + 1} of {Math.ceil(total / pageSize)}
              </span>
              <button
                onClick={() => setPage(page + 1)}
                disabled={(page + 1) * pageSize >= total}
                className="btn-secondary"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default AuditEventList;
