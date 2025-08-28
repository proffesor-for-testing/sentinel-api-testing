import React from 'react';
import { AlertTriangle, Trash2, X } from 'lucide-react';

const ConfirmationModal = ({ 
  show, 
  title, 
  message, 
  confirmText = 'Confirm', 
  cancelText = 'Cancel',
  confirmStyle = 'danger', // 'danger', 'warning', 'primary'
  onConfirm, 
  onCancel,
  icon = null
}) => {
  if (!show) return null;

  const confirmStyles = {
    danger: 'bg-red-600 hover:bg-red-700 text-white',
    warning: 'bg-yellow-600 hover:bg-yellow-700 text-white',
    primary: 'bg-blue-600 hover:bg-blue-700 text-white'
  };

  const iconColors = {
    danger: 'text-red-500',
    warning: 'text-yellow-500',
    primary: 'text-blue-500'
  };

  const defaultIcons = {
    danger: <Trash2 className="w-6 h-6" />,
    warning: <AlertTriangle className="w-6 h-6" />,
    primary: <AlertTriangle className="w-6 h-6" />
  };

  const displayIcon = icon || defaultIcons[confirmStyle];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
        <div className="p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-start space-x-3">
              <div className={iconColors[confirmStyle]}>
                {displayIcon}
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-lg text-gray-900 mb-1">
                  {title}
                </h3>
                <p className="text-sm text-gray-600">
                  {message}
                </p>
              </div>
            </div>
            <button
              onClick={onCancel}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="flex justify-end space-x-3">
            <button
              onClick={onCancel}
              className="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg font-medium transition-colors"
            >
              {cancelText}
            </button>
            <button
              onClick={onConfirm}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${confirmStyles[confirmStyle]}`}
            >
              {confirmText}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;