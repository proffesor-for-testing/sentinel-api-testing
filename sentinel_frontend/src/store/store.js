import { configureStore } from '@reduxjs/toolkit';
import specificationsReducer from '../features/specifications/specificationsSlice';

export const store = configureStore({
  reducer: {
    specifications: specificationsReducer,
  },
});