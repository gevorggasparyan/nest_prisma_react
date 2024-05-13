import { createSlice } from '@reduxjs/toolkit'

import { signIn, signUp } from './actions'
import type { IAuthInitialState } from './types'

export const initialState: IAuthInitialState = {
  signIn: {
    data: null,
    error: null,
    loading: false,
  },
  signUp: {
    loading: false,
    error: null,
    data: null,
  },
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {},
  extraReducers: builder => {
    builder.addCase(signIn.pending, state => {
      state.signIn.loading = true
      state.signIn.error = null
    })

    builder.addCase(signIn.fulfilled, (state, { payload }) => {
      state.signIn.loading = false
      state.signIn.error = null
      state.signIn.data = payload
    })

    builder.addCase(signIn.rejected, (state, action) => {
      state.signIn.loading = false
      state.signIn.error = action.payload as null
    })

    //
    //
    builder.addCase(signUp.pending, state => {
      state.signUp.error = null
      state.signUp.loading = true
    })
    builder.addCase(signUp.fulfilled, (state, action) => {
      state.signUp.error = null
      state.signUp.loading = false
      state.signUp.data = action.payload
    })
    builder.addCase(signUp.rejected, (state, action) => {
      state.signUp.error = action.payload as null
      state.signUp.loading = false
    })
  },
})

export const { name, actions } = authSlice

const authReducer = authSlice.reducer

export default authReducer
