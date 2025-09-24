# Database Setup and Management

## Problem We're Solving

Previously, we had to manually fix database tables one by one when columns were missing, which was:
- Time-consuming and error-prone
- Frustrating for development
- Causing test failures due to missing schema elements

## Solution

We now have a comprehensive database initialization system that:
1. **Creates all tables with all required columns** at once
2. **Automatically initializes on service startup**
3. **Provides easy management commands** via Makefile

## Quick Start

### First-Time Setup
```bash
# Complete setup from scratch (recommended)
make setup

# Or manually:
make build
make init-db
make start
```

### Daily Development
```bash
# Start all services
make start

# Stop all services
make stop

# Restart services
make restart

# Check status
make status
```

### Database Management
```bash
# Initialize/repair database
make init-db

# Reset database (WARNING: data loss)
make reset-db

# Backup database
make backup-db

# Restore from backup
make restore-db
```

## What Gets Created

The `init_db.sql` script creates:

### Core Tables
- **users** - User authentication and profiles
- **projects** - Project organization
- **api_specifications** - OpenAPI/Swagger specs

### Testing Tables
- **test_cases** - Individual test definitions with ALL fields including:
  - description, tags (previously missing)
- **test_suites** - Collections of test cases
- **test_suite_entries** - Links cases to suites (junction table)
- **test_runs** - Execution records
- **test_results** - Detailed results with ALL fields including:
  - response_code, response_headers, response_body
  - latency_ms, assertion_failures (previously missing)

### Indexes
- Performance indexes on foreign keys and commonly queried fields

### Default Data
- Admin user (admin@sentinel.com / admin123)

## Architecture

```
┌─────────────────┐
│ docker-compose  │
│     up -d       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Service Starts  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ init_database.py│
│   (automatic)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  init_db.sql    │
│  (if needed)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Service Ready   │
└─────────────────┘
```

## Files

### `/sentinel_backend/init_db.sql`
Complete SQL script with all table definitions and columns.

### `/sentinel_backend/init_database.py`
Python script that:
- Waits for database availability
- Checks if tables exist
- Runs initialization if needed
- Verifies all columns are present

### `/sentinel_backend/docker-entrypoint.sh`
Entrypoint script that runs initialization before starting services.

### `/Makefile`
Convenient commands for common operations.

## Troubleshooting

### Missing Columns
If you still get "column does not exist" errors:
1. Run `make init-db` to apply the schema
2. If that doesn't work, run `make reset-db` (WARNING: data loss)

### Connection Issues
```bash
# Check if database is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Restart database
docker-compose restart db
```

### Clean Start
```bash
# Remove everything and start fresh
make clean
make setup
```

## Adding New Tables/Columns

When adding new database fields:

1. Update `/sentinel_backend/init_db.sql` with the new schema
2. Add migration logic to `init_database.py` if needed
3. Run `make init-db` to apply changes
4. Commit both files to version control

## Best Practices

1. **Always use the init script** for new deployments
2. **Keep init_db.sql updated** when schema changes
3. **Use make commands** instead of manual docker-compose
4. **Backup before reset** - use `make backup-db` before `make reset-db`
5. **Test locally first** before deploying schema changes

## Migration Strategy

For production environments, consider using:
- Alembic (Python) for version-controlled migrations
- Flyway or Liquibase for enterprise deployments
- Custom migration scripts with version tracking

## Environment Variables

The system uses these database environment variables:
- `DB_HOST` - Database host (default: db)
- `DB_PORT` - Database port (default: 5432)
- `DB_NAME` - Database name (default: sentinel_db)
- `DB_USER` - Database user (default: sentinel)
- `DB_PASSWORD` - Database password (default: sentinel_password)

## Security Notes

1. Change default passwords in production
2. Use environment variables for sensitive data
3. Restrict database access in production
4. Enable SSL for database connections
5. Regular backups are essential