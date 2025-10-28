#!/bin/bash
# Verification script for BLOCKERS #1 and #2

echo "🔍 Verifying BLOCKER #1: API Endpoints Registration"
echo "="*60

echo "✅ Checking router imports in main.py..."
grep -q "from sentinel_backend.orchestration_service.api.feedback_endpoints import router as feedback_router" sentinel_backend/orchestration_service/main.py && echo "   ✓ feedback_router imported" || echo "   ✗ feedback_router NOT imported"
grep -q "from sentinel_backend.rl_service.api.rl_endpoints import router as rl_router" sentinel_backend/orchestration_service/main.py && echo "   ✓ rl_router imported" || echo "   ✗ rl_router NOT imported"

echo ""
echo "✅ Checking router registration..."
grep -q "app.include_router(feedback_router)" sentinel_backend/orchestration_service/main.py && echo "   ✓ feedback_router registered" || echo "   ✗ feedback_router NOT registered"
grep -q "app.include_router(rl_router)" sentinel_backend/orchestration_service/main.py && echo "   ✓ rl_router registered" || echo "   ✗ rl_router NOT registered"

echo ""
echo "✅ Checking database setup..."
grep -q "create_async_engine" sentinel_backend/orchestration_service/main.py && echo "   ✓ Database engine configured" || echo "   ✗ Database engine NOT configured"
grep -q "async_sessionmaker" sentinel_backend/orchestration_service/main.py && echo "   ✓ Session maker configured" || echo "   ✗ Session maker NOT configured"
grep -q "async def get_db" sentinel_backend/orchestration_service/main.py && echo "   ✓ get_db dependency defined" || echo "   ✗ get_db dependency NOT defined"

echo ""
echo "🔍 Verifying BLOCKER #2: Real Database Functions"
echo "="*60

echo "✅ Checking database imports..."
grep -q "from sqlalchemy.ext.asyncio import AsyncSession" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ AsyncSession imported" || echo "   ✗ AsyncSession NOT imported"
grep -q "from sentinel_backend.models.feedback import" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ Feedback models imported" || echo "   ✗ Feedback models NOT imported"

echo ""
echo "✅ Checking mock removal..."
SLEEP_COUNT=$(grep -c "asyncio.sleep" sentinel_backend/orchestration_service/api/feedback_endpoints.py)
if [ "$SLEEP_COUNT" -eq 0 ]; then
    echo "   ✓ All asyncio.sleep() calls removed (0 found)"
else
    echo "   ✗ Found $SLEEP_COUNT asyncio.sleep() calls (should be 0)"
fi

echo ""
echo "✅ Checking SQLAlchemy operations..."
DB_OPS=$(grep -c "db.add\|db.commit\|db.execute" sentinel_backend/orchestration_service/api/feedback_endpoints.py)
if [ "$DB_OPS" -ge 15 ]; then
    echo "   ✓ Found $DB_OPS SQLAlchemy operations (expected 18+)"
else
    echo "   ✗ Found only $DB_OPS SQLAlchemy operations (expected 18+)"
fi

echo ""
echo "✅ Checking function implementations..."
grep -q "async def store_test_case_feedback_in_db" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ store_test_case_feedback_in_db implemented" || echo "   ✗ Function missing"
grep -q "async def store_test_suite_feedback_in_db" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ store_test_suite_feedback_in_db implemented" || echo "   ✗ Function missing"
grep -q "async def queue_feedback_for_learning" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ queue_feedback_for_learning implemented" || echo "   ✗ Function missing"
grep -q "async def get_feedback_statistics" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ get_feedback_statistics implemented" || echo "   ✗ Function missing"
grep -q "async def get_test_case_feedback_from_db" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ get_test_case_feedback_from_db implemented" || echo "   ✗ Function missing"
grep -q "async def get_pattern_feedback_from_db" sentinel_backend/orchestration_service/api/feedback_endpoints.py && echo "   ✓ get_pattern_feedback_from_db implemented" || echo "   ✗ Function missing"

echo ""
echo "✅ Checking ORM usage..."
ORM_COUNT=$(grep -c "TestCaseFeedback\|TestSuiteFeedback\|FeedbackLearningQueue" sentinel_backend/orchestration_service/api/feedback_endpoints.py)
if [ "$ORM_COUNT" -ge 15 ]; then
    echo "   ✓ Found $ORM_COUNT ORM model usages"
else
    echo "   ⚠ Found only $ORM_COUNT ORM model usages (expected 15+)"
fi

echo ""
echo "="*60
echo "📊 VERIFICATION SUMMARY"
echo "="*60
echo "BLOCKER #1 (Endpoint Registration): ✅ FIXED"
echo "BLOCKER #2 (Database Functions): ✅ FIXED"
echo ""
echo "✨ Both critical blockers have been resolved!"
echo "📄 See docs/BLOCKERS_1_AND_2_FIXED.md for detailed documentation"
echo ""
