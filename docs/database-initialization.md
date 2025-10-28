# Database Initialization and Health Checks

## Overview

This document describes the enhanced database initialization and health check system for the Sentinel platform.

## Architecture

### Components

1. **Health Check Script** (`db_health_check.py`)
   - Liveness checks (database responding)
   - Readiness checks (database fully initialized)
   - pgvector extension verification
   - Connection pool monitoring
   - Performance metrics

2. **Diagnostics Tool** (`db_diagnostics.py`)
   - Comprehensive database analysis
   - Table and index health
   - Lock detection
   - Performance profiling
   - Issue identification with recommendations

3. **Initialization with Retry** (`init_db_with_retry.py`)
   - Exponential backoff retry logic
   - Atomic operations with rollback
   - Pre-initialization validation
   - Comprehensive error reporting

4. **Shell Scripts**
   - `wait_for_db.sh` - Wait for database in containers
   - `db_quick_check.sh` - Fast health check for Docker

## Usage

### Quick Start

```bash
# Complete database setup
make init-db

# Check database health
make db-health

# Run comprehensive diagnostics
make db-diagnostics

# Wait for database to be ready
make db-ready

# Reset database (destructive)
make reset-db
```

### Python Scripts

#### Health Check

```bash
# Standard health check
python3 sentinel_backend/scripts/db_health_check.py

# Detailed health check with metrics
python3 sentinel_backend/scripts/db_health_check.py --detailed

# JSON output
python3 sentinel_backend/scripts/db_health_check.py --json

# Liveness check (quick)
python3 sentinel_backend/scripts/db_health_check.py --liveness

# Readiness check (full validation)
python3 sentinel_backend/scripts/db_health_check.py --readiness
```

#### Diagnostics

```bash
# Full diagnostics
python3 sentinel_backend/scripts/db_diagnostics.py

# JSON output
python3 sentinel_backend/scripts/db_diagnostics.py --json
```

#### Initialization

```bash
# Initialize with retry logic
python3 sentinel_backend/scripts/init_db_with_retry.py
```

### Docker Integration

The enhanced health checks are integrated into docker-compose.yml:

```yaml
db:
  healthcheck:
    test: ["CMD-SHELL", "pg_isready && pgvector_check"]
    interval: 10s
    timeout: 5s
    retries: 10
    start_period: 30s
```

Services that depend on the database use:

```yaml
depends_on:
  db:
    condition: service_healthy
```

## Health Check Details

### Checks Performed

1. **Database Connection** (Liveness)
   - Can connect to PostgreSQL
   - Basic query execution
   - Connection timeout handling

2. **pgvector Extension**
   - Extension installed
   - Version check
   - Functional test with vector operations

3. **Tables Exist**
   - All required tables present
   - Proper schema structure

4. **Schema Validity**
   - Critical columns exist
   - Indexes created
   - Foreign key constraints

5. **Connection Pool**
   - Active connections
   - Idle connections
   - Usage percentage
   - Warning on high usage (>80%)

6. **Performance** (Detailed mode)
   - Cache hit ratio
   - Query latency
   - Slow query detection

7. **Database Size** (Detailed mode)
   - Total database size
   - Individual table sizes
   - Growth monitoring

## Diagnostics Details

### Information Gathered

1. **Connection Information**
   - PostgreSQL version
   - Current database and user
   - Active connection counts
   - Connection states

2. **Extensions**
   - Installed extensions with versions
   - pgvector functionality test
   - Extension availability

3. **Tables**
   - Table sizes and row counts
   - Dead row detection
   - Vacuum status
   - Missing table identification

4. **Indexes**
   - Index sizes and usage
   - Unused index detection
   - Performance impact analysis

5. **Performance**
   - Cache hit ratios
   - Slow query detection
   - Query latency measurements

6. **Locks**
   - Current locks
   - Blocked queries
   - Lock contention

### Issue Severity Levels

- **Critical**: Prevents normal operation (missing tables, connection failure)
- **High**: Significant performance or reliability impact
- **Medium**: Optimization opportunities
- **Low**: Minor issues or informational

### Recommendations

The diagnostics tool provides actionable recommendations:

- Missing extension installation
- Table vacuum suggestions
- Index optimization
- Configuration tuning
- Performance improvements

## Retry Logic

### Exponential Backoff

The initialization script uses exponential backoff:

- Initial delay: 1 second
- Maximum delay: 60 seconds
- Backoff multiplier: 2x
- Maximum attempts: 10

Formula: `delay = min(1 * 2^attempt, 60)`

### Retry Scenarios

1. **Database Not Ready**
   - Service starting up
   - Container initialization
   - Network delays

2. **Extension Issues**
   - pgvector not yet available
   - Permission problems

3. **Schema Problems**
   - Table creation conflicts
   - Index creation delays

## Error Handling

### Atomic Operations

All database modifications use transactions:

```python
try:
    cursor.execute(sql_script)
    conn.commit()
except Exception as e:
    conn.rollback()
    raise
```

### Error Messages

Clear, actionable error messages:

```
❌ Database initialization failed: pgvector extension not available
   Recommendation: Ensure pgvector/pgvector:pg16 image is used
```

### Exit Codes

Scripts use standard exit codes:
- `0`: Success
- `1`: Failure (with error messages)

## Environment Variables

### Database Configuration

```bash
DB_HOST=localhost          # Database host
DB_PORT=5432              # Database port
DB_NAME=sentinel_db       # Database name
DB_USER=sentinel          # Database user
DB_PASSWORD=***           # Database password
```

### Retry Configuration

```bash
MAX_RETRIES=10           # Maximum retry attempts
INITIAL_RETRY_DELAY=1    # Initial delay in seconds
MAX_RETRY_DELAY=60       # Maximum delay in seconds
```

## Docker Compose Integration

### Health Check Configuration

```yaml
healthcheck:
  test: ["CMD-SHELL", "health_check_command"]
  interval: 10s      # Check every 10 seconds
  timeout: 5s        # Fail if check takes >5s
  retries: 10        # Try 10 times before unhealthy
  start_period: 30s  # Grace period on startup
```

### Service Dependencies

```yaml
service:
  depends_on:
    db:
      condition: service_healthy  # Wait for db to be healthy
```

## Monitoring

### Metrics Collected

- Connection pool usage
- Query performance
- Cache hit ratios
- Table sizes
- Lock statistics
- Extension versions

### JSON Output

All tools support JSON output for monitoring integration:

```bash
python3 db_health_check.py --json | jq .
```

Example output:

```json
{
  "timestamp": "2025-10-27T16:30:00Z",
  "duration_ms": 145.23,
  "healthy": true,
  "ready": true,
  "checks": {
    "database_connection": {
      "passed": true,
      "message": "Connected to PostgreSQL 16.0"
    },
    "pgvector_extension": {
      "passed": true,
      "message": "pgvector v0.5.1 functional"
    }
  },
  "metrics": {
    "connection_pool": {
      "total": 5,
      "active": 2,
      "idle": 3,
      "usage_percent": 5.0
    }
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused

```bash
# Check if database is running
docker ps | grep sentinel_db

# Check logs
docker logs sentinel_db

# Try manual connection
docker exec -it sentinel_db psql -U sentinel -d sentinel_db
```

#### 2. pgvector Not Available

```bash
# Check image version
docker images | grep pgvector

# Recreate with correct image
docker-compose down -v
docker-compose up -d db
```

#### 3. Tables Not Created

```bash
# Run diagnostics
make db-diagnostics

# Check initialization logs
docker logs sentinel_db

# Manual initialization
make init-db
```

#### 4. Slow Performance

```bash
# Run diagnostics
make db-diagnostics

# Check cache hit ratio
# Should be >90%

# Check connection pool
# Should be <80% usage
```

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python3 sentinel_backend/scripts/db_health_check.py --detailed
```

## Performance Considerations

### Health Check Overhead

- **Liveness check**: <10ms
- **Readiness check**: <100ms
- **Full health check**: <500ms
- **Diagnostics**: 1-5 seconds

### Docker Health Check

Optimized for minimal overhead:
- Simple queries only
- No table scans
- Fast failure detection

### Production Recommendations

1. Use `--readiness` for startup validation
2. Use quick checks for ongoing monitoring
3. Run full diagnostics periodically (e.g., hourly)
4. Monitor metrics in JSON format
5. Set up alerting on critical issues

## Testing

### Manual Testing

```bash
# Test database connection
make db-health

# Test initialization
make reset-db
make init-db

# Test health checks
python3 sentinel_backend/scripts/db_health_check.py --liveness
python3 sentinel_backend/scripts/db_health_check.py --readiness

# Test diagnostics
make db-diagnostics
```

### Automated Testing

```bash
# Integration tests
cd sentinel_backend
./run_tests.sh -d -k test_database

# Health check tests
pytest tests/test_db_health.py -v
```

## Maintenance

### Regular Tasks

1. **Daily**: Monitor health check metrics
2. **Weekly**: Run full diagnostics
3. **Monthly**: Review recommendations
4. **Quarterly**: Optimize based on usage patterns

### Backup and Recovery

```bash
# Backup database
make backup-db

# Restore database
make restore-db FILE=backups/backup_20251027.sql

# Test backup integrity
make db-health
```

## Future Enhancements

1. **Real-time Monitoring**
   - Integration with Prometheus
   - Grafana dashboards
   - Alerting rules

2. **Advanced Diagnostics**
   - Query plan analysis
   - Replication lag monitoring
   - WAL archiving status

3. **Automated Recovery**
   - Self-healing on detected issues
   - Automatic vacuum scheduling
   - Index rebuild automation

4. **Performance Tuning**
   - Adaptive configuration
   - Machine learning-based optimization
   - Predictive maintenance

## References

- PostgreSQL Documentation: https://www.postgresql.org/docs/
- pgvector Extension: https://github.com/pgvector/pgvector
- Docker Health Checks: https://docs.docker.com/engine/reference/builder/#healthcheck
- Connection Pooling: https://www.postgresql.org/docs/current/runtime-config-connection.html
