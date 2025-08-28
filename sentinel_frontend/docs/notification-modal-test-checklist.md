# Notification Modal Test Checklist

## Overview
This checklist helps verify that the custom notification modal is working correctly after replacing native JavaScript alerts.

## Visual Tests

### ✅ Success Notification
- [ ] Delete a single test run
- [ ] Verify green success icon (CheckCircle) appears
- [ ] Verify message shows: "Test run deleted successfully"
- [ ] Verify modal auto-dismisses after 5 seconds
- [ ] Verify OK button closes modal immediately
- [ ] Verify X button closes modal immediately

### ✅ Bulk Delete Notification
- [ ] Select multiple test runs using checkboxes
- [ ] Click "Delete Selected" button
- [ ] Confirm deletion in confirmation modal
- [ ] Verify success notification shows count: "X test runs deleted successfully"
- [ ] Verify modal styling matches app theme

### ❌ Error Notification
- [ ] Attempt to delete when backend is down
- [ ] Verify red error icon (XCircle) appears
- [ ] Verify error message is displayed
- [ ] Verify modal can be closed manually

### ⚠️ Warning Notification (if applicable)
- [ ] Trigger a warning scenario
- [ ] Verify yellow warning icon (AlertTriangle) appears
- [ ] Verify warning message is displayed

## Functional Tests

### Modal Behavior
- [ ] Modal appears centered on screen
- [ ] Background overlay prevents interaction with page
- [ ] Modal has proper z-index (appears above other content)
- [ ] Multiple notifications don't stack (new replaces old)
- [ ] Modal is responsive on different screen sizes

### Integration Tests
- [ ] Test runs list refreshes after successful delete
- [ ] Selection state clears after bulk delete
- [ ] Error notifications don't refresh the list
- [ ] Network errors are properly caught and displayed

## Accessibility Tests
- [ ] Modal can be closed with Escape key (if implemented)
- [ ] Focus management when modal opens/closes
- [ ] Screen reader compatibility (ARIA labels)
- [ ] Keyboard navigation works properly

## Performance Tests
- [ ] Modal appears immediately without lag
- [ ] Auto-dismiss timer works accurately (5 seconds)
- [ ] No memory leaks from repeated notifications
- [ ] Modal transitions are smooth

## Edge Cases
- [ ] Rapid clicking doesn't create multiple modals
- [ ] Deleting last test run shows appropriate message
- [ ] Empty bulk selection shows appropriate warning
- [ ] Very long error messages display properly

## Browser Compatibility
- [ ] Chrome
- [ ] Firefox
- [ ] Safari
- [ ] Edge

## Notes
- Original issue: Native JS alert() was showing "localhost:3000 says"
- Solution: Custom React modal component with styled notifications
- Auto-dismiss: 5 seconds default timeout
- Icons: Lucide React icons (CheckCircle, XCircle, AlertTriangle)