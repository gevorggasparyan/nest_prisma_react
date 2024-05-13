import { createSlice } from '@reduxjs/toolkit'

import type { TUserState } from './types'
import { getProfileData } from './actions'

const initialState: TUserState = {
  data: {
    user: null,
    error: null,
    loading: false,
  },
}

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {},
  extraReducers: builder => {
    builder
      .addCase(getProfileData.pending, state => {
        state.data.loading = true
        state.data.error = null
      })
      .addCase(getProfileData.rejected, (state, action) => {
        state.data.loading = false
        state.data.error = action.payload as null
      })
      .addCase(getProfileData.fulfilled, (state, action) => {
        state.data.loading = false
        state.data.error = null
        state.data.user = action.payload
      })
  },
})

const userSliceReducer = userSlice.reducer

export default userSliceReducer
