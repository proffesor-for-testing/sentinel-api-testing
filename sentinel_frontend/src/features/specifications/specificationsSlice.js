import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  specifications: [],
  status: 'idle',
  error: null,
};

const specificationsSlice = createSlice({
  name: 'specifications',
  initialState,
  reducers: {},
  extraReducers: (builder) => {},
});

export default specificationsSlice.reducer;