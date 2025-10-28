#!/usr/bin/env python3
"""
Script to fix feedback_endpoints.py by adding database session dependencies.
"""

import re

def fix_feedback_endpoints():
    """Apply all necessary fixes to feedback_endpoints.py"""

    file_path = "/workspaces/api-testing-agents/sentinel_backend/orchestration_service/api/feedback_endpoints.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # Fix 1: Add get_db import
    if "from sentinel_backend.orchestration_service.main import get_db" not in content:
        content = content.replace(
            "from sentinel_backend.models.feedback import (",
            "from sentinel_backend.orchestration_service.main import get_db\nfrom sentinel_backend.models.feedback import ("
        )
        print("✓ Added get_db import")

    # Fix 2: Fix submit_test_case_feedback function signature
    content = re.sub(
        r'(@router\.post\("/test-case".*?\n.*?async def submit_test_case_feedback\(\s*feedback: TestCaseFeedbackRequest,\s*request: Request,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\))(.*?\n\) -> TestCaseFeedbackResponse:)',
        r'\1,\n    db: AsyncSession = Depends(get_db)\3',
        content,
        flags=re.DOTALL
    )
    print("✓ Fixed submit_test_case_feedback signature")

    # Fix 3: Fix submit_test_case_feedback db parameter passing
    content = content.replace(
        'stored_feedback = await store_test_case_feedback_in_db(\n            feedback, user_id, correlation_id\n        )',
        'stored_feedback = await store_test_case_feedback_in_db(\n            feedback, user_id, correlation_id, db\n        )'
    )
    content = content.replace(
        'queued = await queue_feedback_for_learning(\n            feedback_id=stored_feedback["feedback_id"],\n            feedback_type="test_case",\n            priority="high" if feedback.found_issue else "normal"\n        )',
        'queued = await queue_feedback_for_learning(\n            feedback_id=stored_feedback["feedback_id"],\n            feedback_type="test_case",\n            db=db,\n            priority="high" if feedback.found_issue else "normal"\n        )'
    )
    print("✓ Fixed submit_test_case_feedback db passing")

    # Fix 4: Fix submit_test_suite_feedback function signature
    content = re.sub(
        r'(@router\.post\("/test-suite".*?\n.*?async def submit_test_suite_feedback\(\s*feedback: TestSuiteFeedbackRequest,\s*request: Request,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\))(.*?\n\) -> TestSuiteFeedbackResponse:)',
        r'\1,\n    db: AsyncSession = Depends(get_db)\3',
        content,
        flags=re.DOTALL
    )
    print("✓ Fixed submit_test_suite_feedback signature")

    # Fix 5: Fix submit_test_suite_feedback db parameter passing
    content = content.replace(
        'stored_feedback = await store_test_suite_feedback_in_db(\n            feedback, user_id, correlation_id\n        )',
        'stored_feedback = await store_test_suite_feedback_in_db(\n            feedback, user_id, correlation_id, db\n        )'
    )
    content = content.replace(
        'queued = await queue_feedback_for_learning(\n            feedback_id=stored_feedback["feedback_id"],\n            feedback_type="test_suite",\n            priority="high" if feedback.coverage_gaps else "normal"\n        )',
        'queued = await queue_feedback_for_learning(\n            feedback_id=stored_feedback["feedback_id"],\n            feedback_type="test_suite",\n            db=db,\n            priority="high" if feedback.coverage_gaps else "normal"\n        )'
    )
    print("✓ Fixed submit_test_suite_feedback db passing")

    # Fix 6: Fix get_feedback_stats function signature
    content = re.sub(
        r'(@router\.get\("/statistics".*?\n.*?async def get_feedback_stats\(\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\))(.*?\n\) -> FeedbackStatistics:)',
        r'\1,\n    db: AsyncSession = Depends(get_db)\3',
        content,
        flags=re.DOTALL
    )
    content = content.replace(
        'stats = await get_feedback_statistics()',
        'stats = await get_feedback_statistics(db)'
    )
    print("✓ Fixed get_feedback_stats signature and call")

    # Fix 7: Fix get_test_case_feedback function signature
    content = re.sub(
        r'(@router\.get\("/test-case/\{test_id\}".*?\n.*?async def get_test_case_feedback\(\s*test_id: str,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\))(.*?\n\) -> Dict\[str, Any\]:)',
        r'\1,\n    db: AsyncSession = Depends(get_db)\3',
        content,
        flags=re.DOTALL
    )
    content = content.replace(
        'feedback_list = await get_test_case_feedback_from_db(test_id)',
        'feedback_list = await get_test_case_feedback_from_db(test_id, db)'
    )
    print("✓ Fixed get_test_case_feedback signature and call")

    # Fix 8: Fix get_pattern_feedback function signature
    content = re.sub(
        r'(@router\.get\("/patterns/\{pattern_id\}".*?\n.*?async def get_pattern_feedback\(\s*pattern_id: str,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\))(.*?\n\) -> Dict\[str, Any\]:)',
        r'\1,\n    db: AsyncSession = Depends(get_db)\3',
        content,
        flags=re.DOTALL
    )
    content = content.replace(
        'pattern_feedback = await get_pattern_feedback_from_db(pattern_id)',
        'pattern_feedback = await get_pattern_feedback_from_db(pattern_id, db)'
    )
    print("✓ Fixed get_pattern_feedback signature and call")

    # Write back
    with open(file_path, 'w') as f:
        f.write(content)

    print("\n✅ All fixes applied successfully!")
    print(f"✅ File updated: {file_path}")

if __name__ == "__main__":
    fix_feedback_endpoints()
