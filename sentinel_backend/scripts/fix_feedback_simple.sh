#!/bin/bash
set -e

FILE="/workspaces/api-testing-agents/sentinel_backend/orchestration_service/api/feedback_endpoints.py"

echo "Applying fixes to feedback_endpoints.py..."

# Backup original
cp "$FILE" "${FILE}.backup"

# Fix 1: Replace function calls to add db parameter
sed -i 's/stored_feedback = await store_test_case_feedback_in_db(\n            feedback, user_id, correlation_id$/stored_feedback = await store_test_case_feedback_in_db(\n            feedback, user_id, correlation_id, db/g' "$FILE"

sed -i 's/feedback, user_id, correlation_id$/&, db/g' "$FILE"

sed -i 's/feedback_type="test_case",$/&\n            db=db,/g' "$FILE"

sed -i 's/feedback_type="test_suite",$/&\n            db=db,/g' "$FILE"

sed -i 's/stats = await get_feedback_statistics()/stats = await get_feedback_statistics(db)/g' "$FILE"

sed -i 's/feedback_list = await get_test_case_feedback_from_db(test_id)/feedback_list = await get_test_case_feedback_from_db(test_id, db)/g' "$FILE"

sed -i 's/pattern_feedback = await get_pattern_feedback_from_db(pattern_id)/pattern_feedback = await get_pattern_feedback_from_db(pattern_id, db)/g' "$FILE"

echo "✅ All fixes applied!"
echo "Backup saved to: ${FILE}.backup"
