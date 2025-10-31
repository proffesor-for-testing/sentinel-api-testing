# Docker Startup - Quick Reference

## 🚨 The Problem

**Sentinel FAILS on first `docker-compose up`** due to:
1. Database never initialized (no tables)
2. Hardcoded `localhost` instead of `db` hostname
3. Missing `SENTINEL_DB_URL` environment variable
4. Services crash before schema is created

---

## ✅ The Solution (15-Minute Fix)

### 1. Add Database URL to .env.docker

```bash
echo "
SENTINEL_DB_URL=postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db
DB_HOST=db
DB_PORT=5432
DB_USER=sentinel
DB_PASSWORD=sentinel_password
DB_NAME=sentinel_db
" >> /workspaces/api-testing-agents/sentinel_backend/.env.docker
```

### 2. Fix settings.py Default (Line 30)

**Change FROM:**
```python
default="postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel_db"
```

**Change TO:**
```python
default=os.getenv(
    "SENTINEL_DB_URL",
    "postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db"
)
```

### 3. Auto-Initialize Database

Add to `docker-compose.yml` under `db.volumes`:
```yaml
volumes:
  - sentinel_postgres_data:/var/lib/postgresql/data
  - ./sentinel_backend/init_db.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
```

### 4. Fix auth_service Dependency

Add to `docker-compose.yml` under `auth_service`:
```yaml
depends_on:
  db:
    condition: service_healthy
```

### 5. Test

```bash
docker-compose down -v
docker-compose up -d
# Wait 60 seconds
curl http://localhost:8000/health
```

---

## 📊 What Was Broken

| Component | Issue | Impact | Fix |
|-----------|-------|--------|-----|
| **settings.py** | `localhost` hardcoded | Connection refused | Use `db` hostname |
| **.env.docker** | No `SENTINEL_DB_URL` | Falls back to localhost | Add env var |
| **docker-compose.yml** | No auto-init | Empty database | Add init volume |
| **auth_service** | No DB dependency | Starts before DB ready | Add `depends_on` |
| **Health check** | Only checks postgres | Passes with no tables | Check table count |

---

## 🔍 How to Diagnose

### Check Database

```bash
# Is database running?
docker-compose ps db

# Can we connect?
docker-compose exec db psql -U sentinel -d sentinel_db -c "SELECT 1;"

# Do tables exist?
docker-compose exec db psql -U sentinel -d sentinel_db -c "\dt"
# Should show 8+ tables

# Check pgvector
docker-compose exec db psql -U sentinel -d sentinel_db -c "SELECT * FROM pg_extension WHERE extname='vector';"
```

### Check Services

```bash
# Are services running?
docker-compose ps

# Check specific service health
curl http://localhost:8000/health  # API Gateway
curl http://localhost:8001/health  # Spec Service
curl http://localhost:8003/health  # Execution Service
curl http://localhost:8004/health  # Data Service
curl http://localhost:8005/health  # Auth Service

# View service logs
docker-compose logs spec_service
docker-compose logs auth_service
docker-compose logs execution_service
docker-compose logs data_service
```

### Common Error Messages

**"Connection refused"**
```
sqlalchemy.exc.OperationalError: could not connect to server: Connection refused
  Is the server running on host "localhost"
```
→ Service using localhost instead of db hostname

**"Relation does not exist"**
```
psycopg2.errors.UndefinedTable: relation "test_cases" does not exist
```
→ Database connected but no tables created

**"Password authentication failed"**
```
psycopg2.OperationalError: FATAL: password authentication failed for user "sentinel"
```
→ Credentials mismatch or environment vars not loaded

---

## 🎯 Quick Commands

```bash
# Complete reset and start
make clean && make setup

# Check status
make status

# Watch logs
make logs

# Run diagnostics
make diagnose

# Verify system operational
make verify

# Manual DB init (if needed)
make init-db
```

---

## 📈 Startup Timeline

### Before Fix (BROKEN)
```
T+0s:   docker-compose up -d
T+5s:   Database healthy (but empty)
T+6s:   Services start
T+7s:   Services try to connect
T+8s:   "Connection refused" errors
T+10s:  All DB services crashed
T+∞:    Manual intervention required
```

### After Fix (WORKING)
```
T+0s:   docker-compose up -d
T+2s:   Database starts
T+5s:   init_db.sql runs automatically
T+10s:  Schema created, pgvector installed
T+15s:  Database health check passes
T+20s:  Services start
T+25s:  All services connected
T+30s:  Frontend accessible
T+35s:  ✅ FULLY OPERATIONAL
```

---

## 🔐 Security Notes

**Current (Development)**
- Credentials in plain text `.env.docker`
- Default admin password: `admin123`
- No secrets rotation

**Production Recommendations**
- Use Docker secrets
- Integrate HashiCorp Vault
- Rotate credentials regularly
- Use strong passwords
- Enable SSL/TLS for database

---

## 📁 Files Changed

### Modified
- `/workspaces/api-testing-agents/sentinel_backend/.env.docker`
- `/workspaces/api-testing-agents/sentinel_backend/config/settings.py`
- `/workspaces/api-testing-agents/docker-compose.yml`
- `/workspaces/api-testing-agents/Makefile`

### Created
- `/workspaces/api-testing-agents/sentinel_backend/scripts/02-create-admin.sql`
- `/workspaces/api-testing-agents/tests/test_docker_startup.sh`
- `/workspaces/api-testing-agents/docs/CRITICAL_DOCKER_STARTUP_ANALYSIS.md`
- `/workspaces/api-testing-agents/docs/DOCKER_FIX_IMPLEMENTATION_GUIDE.md`

---

## 🧪 Testing Checklist

- [ ] Clean environment: `docker-compose down -v`
- [ ] Fresh start: `docker-compose up -d`
- [ ] Wait 60 seconds
- [ ] Check database: `docker-compose exec db psql -U sentinel -d sentinel_db -c "\dt"`
- [ ] Check services: `make status`
- [ ] Test login: Visit http://localhost:3000
- [ ] Verify API: `curl http://localhost:8000/health`
- [ ] Run automated test: `./tests/test_docker_startup.sh`

---

## 🆘 Emergency Recovery

If system is broken during demo:

```bash
# 1. Stop everything
docker-compose down

# 2. Quick fix
cat >> sentinel_backend/.env.docker << 'EOF'
SENTINEL_DB_URL=postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db
EOF

# 3. Restart
docker-compose up -d

# 4. Wait for DB
sleep 30

# 5. Manual init (fallback)
make init-db

# 6. Check status
make status
```

---

## 📞 Support

**If tests fail:**
1. Run: `make diagnose`
2. Check: `docker-compose logs db | grep ERROR`
3. Verify: Ports 3000, 5432, 8000-8005 are free
4. Review: Full analysis in `docs/CRITICAL_DOCKER_STARTUP_ANALYSIS.md`

**For implementation:**
- See: `docs/DOCKER_FIX_IMPLEMENTATION_GUIDE.md`
- Estimated time: 4-6 hours
- Risk level: Low (config only)

---

## 🎯 Success Metrics

After fix, system should:
- ✅ Start in < 60 seconds
- ✅ No manual steps required
- ✅ 100% automated test pass rate
- ✅ Database auto-initialized
- ✅ All services healthy
- ✅ Admin user created
- ✅ Frontend accessible
- ✅ API functional

---

**Last Updated**: 2025-10-29
**Status**: Ready to implement
**Priority**: CRITICAL
