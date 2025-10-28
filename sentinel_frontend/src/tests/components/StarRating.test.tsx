import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StarRating } from '../../components/feedback/StarRating';

describe('StarRating Component', () => {
  const mockOnChange = jest.fn();

  beforeEach(() => {
    mockOnChange.mockClear();
  });

  describe('Rendering', () => {
    it('should render with default props', () => {
      render(<StarRating value={0} onChange={mockOnChange} />);

      expect(screen.getByRole('group')).toBeInTheDocument();
      expect(screen.getAllByRole('button')).toHaveLength(5);
    });

    it('should render with custom label', () => {
      const label = 'Custom Rating Label';
      render(<StarRating value={0} onChange={mockOnChange} label={label} />);

      expect(screen.getByText(label)).toBeInTheDocument();
    });

    it('should show required asterisk when required', () => {
      render(<StarRating value={0} onChange={mockOnChange} required />);

      expect(screen.getByText('*')).toBeInTheDocument();
    });

    it('should render custom number of stars', () => {
      render(<StarRating value={0} onChange={mockOnChange} maxStars={10} />);

      expect(screen.getAllByRole('button')).toHaveLength(10);
    });

    it('should display current rating value', () => {
      render(<StarRating value={3} onChange={mockOnChange} maxStars={5} />);

      expect(screen.getByText('3 / 5')).toBeInTheDocument();
    });
  });

  describe('Interaction', () => {
    it('should call onChange when star is clicked', () => {
      render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      fireEvent.click(stars[2]); // Click third star

      expect(mockOnChange).toHaveBeenCalledWith(3);
    });

    it('should not call onChange when disabled', () => {
      render(<StarRating value={0} onChange={mockOnChange} disabled />);

      const stars = screen.getAllByRole('button');
      fireEvent.click(stars[2]);

      expect(mockOnChange).not.toHaveBeenCalled();
    });

    it('should update visual state on hover', () => {
      const { container } = render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      fireEvent.mouseEnter(stars[3]);

      // Check that hover styles are applied
      const hoveredStars = container.querySelectorAll('.text-yellow-400');
      expect(hoveredStars.length).toBeGreaterThan(0);
    });

    it('should reset hover state on mouse leave', () => {
      const { container } = render(<StarRating value={2} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      fireEvent.mouseEnter(stars[4]);
      fireEvent.mouseLeave(stars[4]);

      // Should show original value (2 stars)
      const filledStars = container.querySelectorAll('.text-yellow-400');
      expect(filledStars.length).toBe(2);
    });
  });

  describe('Keyboard Navigation', () => {
    it('should select star on Enter key', async () => {
      const user = userEvent.setup();
      render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      stars[2].focus();
      await user.keyboard('{Enter}');

      expect(mockOnChange).toHaveBeenCalledWith(3);
    });

    it('should select star on Space key', async () => {
      const user = userEvent.setup();
      render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      stars[1].focus();
      await user.keyboard(' ');

      expect(mockOnChange).toHaveBeenCalledWith(2);
    });

    it('should navigate with arrow right key', async () => {
      const user = userEvent.setup();
      render(<StarRating value={2} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      stars[1].focus();
      await user.keyboard('{ArrowRight}');

      expect(mockOnChange).toHaveBeenCalledWith(3);
    });

    it('should navigate with arrow left key', async () => {
      const user = userEvent.setup();
      render(<StarRating value={3} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      stars[2].focus();
      await user.keyboard('{ArrowLeft}');

      expect(mockOnChange).toHaveBeenCalledWith(2);
    });

    it('should not navigate beyond boundaries', async () => {
      const user = userEvent.setup();
      render(<StarRating value={5} onChange={mockOnChange} maxStars={5} />);

      const stars = screen.getAllByRole('button');
      stars[4].focus();
      await user.keyboard('{ArrowRight}');

      // Should not increase beyond max
      expect(mockOnChange).not.toHaveBeenCalled();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<StarRating value={0} onChange={mockOnChange} />);

      expect(screen.getByLabelText('1 star')).toBeInTheDocument();
      expect(screen.getByLabelText('2 stars')).toBeInTheDocument();
      expect(screen.getByLabelText('5 stars')).toBeInTheDocument();
    });

    it('should have proper ARIA pressed state', () => {
      render(<StarRating value={3} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      expect(stars[2]).toHaveAttribute('aria-pressed', 'true');
      expect(stars[3]).toHaveAttribute('aria-pressed', 'false');
    });

    it('should have tabindex -1 when disabled', () => {
      render(<StarRating value={0} onChange={mockOnChange} disabled />);

      const stars = screen.getAllByRole('button');
      stars.forEach(star => {
        expect(star).toHaveAttribute('tabindex', '-1');
      });
    });

    it('should have tabindex 0 when enabled', () => {
      render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      stars.forEach(star => {
        expect(star).toHaveAttribute('tabindex', '0');
      });
    });
  });

  describe('Styling', () => {
    it('should apply size classes correctly', () => {
      const { rerender } = render(
        <StarRating value={0} onChange={mockOnChange} size="sm" />
      );

      let stars = screen.getAllByRole('button');
      expect(stars[0]).toHaveClass('w-5', 'h-5');

      rerender(<StarRating value={0} onChange={mockOnChange} size="lg" />);
      stars = screen.getAllByRole('button');
      expect(stars[0]).toHaveClass('w-12', 'h-12');
    });

    it('should apply custom color', () => {
      render(<StarRating value={3} onChange={mockOnChange} color="text-red-500" />);

      const stars = screen.getAllByRole('button');
      expect(stars[0]).toHaveClass('text-red-500');
    });

    it('should show disabled opacity', () => {
      render(<StarRating value={0} onChange={mockOnChange} disabled />);

      const stars = screen.getAllByRole('button');
      expect(stars[0]).toHaveClass('opacity-50');
    });
  });

  describe('Edge Cases', () => {
    it('should handle rapid clicks', () => {
      render(<StarRating value={0} onChange={mockOnChange} />);

      const stars = screen.getAllByRole('button');
      fireEvent.click(stars[0]);
      fireEvent.click(stars[2]);
      fireEvent.click(stars[4]);

      expect(mockOnChange).toHaveBeenCalledTimes(3);
      expect(mockOnChange).toHaveBeenLastCalledWith(5);
    });

    it('should handle value changes from parent', () => {
      const { rerender } = render(
        <StarRating value={2} onChange={mockOnChange} />
      );

      expect(screen.getByText('2 / 5')).toBeInTheDocument();

      rerender(<StarRating value={4} onChange={mockOnChange} />);
      expect(screen.getByText('4 / 5')).toBeInTheDocument();
    });

    it('should handle zero stars edge case', () => {
      render(<StarRating value={0} onChange={mockOnChange} maxStars={0} />);

      expect(screen.queryAllByRole('button')).toHaveLength(0);
    });
  });
});
