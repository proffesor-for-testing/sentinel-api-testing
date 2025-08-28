import { useState, useCallback } from 'react';

const useNotification = () => {
  const [notification, setNotification] = useState({
    show: false,
    type: 'success', // 'success', 'error', 'warning'
    message: ''
  });

  const [confirmation, setConfirmation] = useState({
    show: false,
    title: '',
    message: '',
    confirmText: 'Confirm',
    cancelText: 'Cancel',
    confirmStyle: 'danger',
    onConfirm: null,
    onCancel: null
  });

  const showNotification = useCallback((type, message) => {
    setNotification({
      show: true,
      type,
      message
    });
  }, []);

  const hideNotification = useCallback(() => {
    setNotification(prev => ({ ...prev, show: false }));
  }, []);

  const showSuccess = useCallback((message) => {
    showNotification('success', message);
  }, [showNotification]);

  const showError = useCallback((message) => {
    showNotification('error', message);
  }, [showNotification]);

  const showWarning = useCallback((message) => {
    showNotification('warning', message);
  }, [showNotification]);

  const confirm = useCallback((options) => {
    return new Promise((resolve) => {
      setConfirmation({
        show: true,
        title: options.title || 'Confirm Action',
        message: options.message || 'Are you sure?',
        confirmText: options.confirmText || 'Confirm',
        cancelText: options.cancelText || 'Cancel',
        confirmStyle: options.confirmStyle || 'danger',
        onConfirm: () => {
          setConfirmation(prev => ({ ...prev, show: false }));
          resolve(true);
        },
        onCancel: () => {
          setConfirmation(prev => ({ ...prev, show: false }));
          resolve(false);
        }
      });
    });
  }, []);

  return {
    notification,
    confirmation,
    showNotification,
    hideNotification,
    showSuccess,
    showError,
    showWarning,
    confirm
  };
};

export default useNotification;