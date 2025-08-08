import { configureStore } from '@reduxjs/toolkit';
import specificationsReducer from '../features/specifications/specificationsSlice';
import authReducer from '../features/auth/authSlice';

export const store = configureStore({
  reducer: {
    specifications: specificationsReducer,
    auth: authReducer,
  },
});