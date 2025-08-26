# Bulk Delete Test Plan

## Overview
Test plan for the bulk deletion functionality for test cases on the `/test-cases` page.

## Test Scenarios

### 1. Basic Bulk Deletion
- **Setup**: Have some test cases without dependencies
- **Steps**:
  1. Navigate to Test Cases page
  2. Select 2-3 test cases using checkboxes
  3. Click "Delete Selected" button
  4. Confirm deletion in basic confirmation dialog
- **Expected**: Test cases are deleted successfully, page refreshes

### 2. Select All Functionality  
- **Steps**:
  1. Click "Select All" checkbox
  2. Verify all visible test cases are selected
  3. Click "Select All" again to deselect all
- **Expected**: Select/deselect all works correctly

### 3. Deletion with Test Suite Dependencies
- **Setup**: Create test cases that are part of test suites
- **Steps**:
  1. Select test cases that belong to test suites
  2. Click "Delete Selected"  
  3. Verify dependency modal shows suite information
  4. Click "Force Delete" to proceed
- **Expected**: 
  - Modal shows suite dependencies clearly
  - Force delete removes cases from suites and deletes them
  - Success message shows warnings about suite removal

### 4. Error Handling
- **Test cases**:
  - Try to delete already deleted test cases
  - Test with invalid case IDs
  - Test with server connectivity issues
- **Expected**: Appropriate error messages shown

### 5. UI State Management
- **Verify**:
  - Loading states during deletion
  - Buttons disabled during processing
  - Selection cleared after successful deletion
  - Page refreshes with updated data

## Backend API Testing

### Direct API Calls

```bash
# Test bulk delete without dependencies
curl -X DELETE "http://localhost:8000/api/v1/test-cases/bulk-delete" \
  -H "Content-Type: application/json" \
  -d '{"case_ids": [1, 2, 3]}'

# Test bulk delete with force flag
curl -X DELETE "http://localhost:8000/api/v1/test-cases/bulk-delete" \
  -H "Content-Type: application/json" \
  -d '{"case_ids": [1, 2, 3], "force_delete": true}'

# Test with invalid data
curl -X DELETE "http://localhost:8000/api/v1/test-cases/bulk-delete" \
  -H "Content-Type: application/json" \
  -d '{"case_ids": []}'
```

## Expected API Responses

### Success Response
```json
{
  "message": "Successfully deleted 3 test cases",
  "deleted_count": 3,
  "deleted_case_ids": [1, 2, 3],
  "missing_case_ids": []
}
```

### Dependency Warning Response
```json
{
  "can_delete": false,
  "message": "Test cases have dependencies that must be handled before deletion",
  "dependencies": {
    "suite_dependencies": [
      {
        "case_id": 1,
        "suite_id": 1,
        "suite_name": "API Test Suite"
      }
    ],
    "result_dependencies": []
  },
  "found_cases": 3,
  "missing_cases": [],
  "suggestion": "Use force_delete=true to delete test cases and remove them from suites"
}
```

## UI Elements to Verify

### Test Cases Page
- [x] Checkbox for each test case row
- [x] "Select All" checkbox in header
- [x] "Delete Selected (X)" button appears when items selected
- [x] Button shows loading state during deletion
- [x] Button is disabled when no items selected

### Confirmation Modal
- [x] Shows number of items to be deleted
- [x] Lists test suite dependencies with suite names
- [x] Lists test result dependencies count
- [x] Shows force delete warning
- [x] Has Cancel and Force Delete buttons
- [x] Force Delete button shows loading state

### Success/Error Handling
- [x] Shows success message after deletion
- [x] Shows warnings if test cases removed from suites
- [x] Shows appropriate error messages for failures
- [x] Refreshes test case list after successful deletion

## Manual Testing Checklist

- [ ] Basic test case selection and deletion
- [ ] Select All functionality
- [ ] Delete with suite dependencies
- [ ] Force delete confirmation
- [ ] Error handling for edge cases
- [ ] UI loading states and feedback
- [ ] Page refresh after successful deletion
- [ ] Integration with existing bulk actions