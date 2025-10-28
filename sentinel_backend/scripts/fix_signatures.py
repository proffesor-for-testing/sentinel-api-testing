#!/usr/bin/env python3
"""Fix function signatures to add db parameters."""

import re

FILE_PATH = "/workspaces/api-testing-agents/sentinel_backend/orchestration_service/api/feedback_endpoints.py"

with open(FILE_PATH, 'r') as f:
    content = f.read()

# Check if get_db import exists, if not add it
if "from sentinel_backend.orchestration_service.main import get_db" not in content:
    # Find the line with sentinel_backend.models.feedback import
    content = content.replace(
        "from sentinel_backend.models.feedback import (",
        "from sentinel_backend.orchestration_service.main import get_db\nfrom sentinel_backend.models.feedback import ("
    )
    print("✓ Added get_db import")

# Fix 1: submit_test_case_feedback
pattern1 = r'(async def submit_test_case_feedback\(\s*feedback: TestCaseFeedbackRequest,\s*request: Request,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\)\s*)\) -> TestCaseFeedbackResponse:'
replacement1 = r'\1,\n    db: AsyncSession = Depends(get_db)\n) -> TestCaseFeedbackResponse:'
content = re.sub(pattern1, replacement1, content, flags=re.DOTALL)
print("✓ Fixed submit_test_case_feedback")

# Fix 2: submit_test_suite_feedback
pattern2 = r'(async def submit_test_suite_feedback\(\s*feedback: TestSuiteFeedbackRequest,\s*request: Request,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\)\s*)\) -> TestSuiteFeedbackResponse:'
replacement2 = r'\1,\n    db: AsyncSession = Depends(get_db)\n) -> TestSuiteFeedbackResponse:'
content = re.sub(pattern2, replacement2, content, flags=re.DOTALL)
print("✓ Fixed submit_test_suite_feedback")

# Fix 3: get_feedback_stats
pattern3 = r'(async def get_feedback_stats\(\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\)\s*)\) -> FeedbackStatistics:'
replacement3 = r'\1,\n    db: AsyncSession = Depends(get_db)\n) -> FeedbackStatistics:'
content = re.sub(pattern3, replacement3, content, flags=re.DOTALL)
print("✓ Fixed get_feedback_stats")

# Fix 4: get_test_case_feedback
pattern4 = r'(async def get_test_case_feedback\(\s*test_id: str,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\)\s*)\) -> Dict\[str, Any\]:'
replacement4 = r'\1,\n    db: AsyncSession = Depends(get_db)\n) -> Dict[str, Any]:'
content = re.sub(pattern4, replacement4, content, flags=re.DOTALL)
print("✓ Fixed get_test_case_feedback")

# Fix 5: get_pattern_feedback
pattern5 = r'(async def get_pattern_feedback\(\s*pattern_id: str,\s*current_user: Dict\[str, Any\] = Depends\(get_current_user\)\s*)\) -> Dict\[str, Any\]:'
replacement5 = r'\1,\n    db: AsyncSession = Depends(get_db)\n) -> Dict[str, Any]:'
content = re.sub(pattern5, replacement5, content, flags=re.DOTALL)
print("✓ Fixed get_pattern_feedback")

with open(FILE_PATH, 'w') as f:
    f.write(content)

print("\n✅ All function signatures fixed!")
