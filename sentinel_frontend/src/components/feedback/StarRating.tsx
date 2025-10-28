import React, { useState, useCallback, KeyboardEvent } from 'react';

export interface StarRatingProps {
  value: number;
  onChange: (rating: number) => void;
  maxStars?: number;
  size?: 'sm' | 'md' | 'lg';
  color?: string;
  disabled?: boolean;
  required?: boolean;
  label?: string;
}

/**
 * StarRating Component
 * Interactive star rating with keyboard navigation and accessibility support
 */
export const StarRating: React.FC<StarRatingProps> = ({
  value,
  onChange,
  maxStars = 5,
  size = 'md',
  color = 'text-yellow-400',
  disabled = false,
  required = false,
  label = 'Rate this test case'
}) => {
  const [hoverValue, setHoverValue] = useState<number>(0);

  const sizeClasses = {
    sm: 'w-5 h-5',
    md: 'w-8 h-8',
    lg: 'w-12 h-12'
  };

  const handleClick = useCallback((rating: number) => {
    if (!disabled) {
      onChange(rating);
    }
  }, [disabled, onChange]);

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>, index: number) => {
    if (disabled) return;

    const rating = index + 1;

    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault();
        handleClick(rating);
        break;
      case 'ArrowRight':
      case 'ArrowUp':
        event.preventDefault();
        if (rating < maxStars) {
          handleClick(rating + 1);
          const nextElement = event.currentTarget.nextElementSibling as HTMLElement;
          nextElement?.focus();
        }
        break;
      case 'ArrowLeft':
      case 'ArrowDown':
        event.preventDefault();
        if (rating > 1) {
          handleClick(rating - 1);
          const prevElement = event.currentTarget.previousElementSibling as HTMLElement;
          prevElement?.focus();
        }
        break;
      default:
        break;
    }
  };

  return (
    <div className="star-rating-container" role="group" aria-label={label}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 mb-2">
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}
      <div className="flex items-center space-x-1">
        {Array.from({ length: maxStars }, (_, index) => {
          const starValue = index + 1;
          const isFilled = starValue <= (hoverValue || value);

          return (
            <div
              key={index}
              role="button"
              tabIndex={disabled ? -1 : 0}
              aria-label={`${starValue} star${starValue > 1 ? 's' : ''}`}
              aria-pressed={starValue === value}
              className={`
                star-icon cursor-pointer transition-all duration-200
                ${sizeClasses[size]}
                ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:scale-110'}
                ${isFilled ? color : 'text-gray-300'}
              `}
              onClick={() => handleClick(starValue)}
              onMouseEnter={() => !disabled && setHoverValue(starValue)}
              onMouseLeave={() => !disabled && setHoverValue(0)}
              onKeyDown={(e) => handleKeyDown(e, index)}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="currentColor"
                className="w-full h-full"
              >
                <path
                  fillRule="evenodd"
                  d="M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.007 5.404.433c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.433 2.082-5.006z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
          );
        })}
        {value > 0 && (
          <span className="ml-2 text-sm text-gray-600" aria-live="polite">
            {value} / {maxStars}
          </span>
        )}
      </div>
    </div>
  );
};

export default StarRating;
