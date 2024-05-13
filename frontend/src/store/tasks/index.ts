import { createSlice } from '@reduxjs/toolkit'

import type { TUserState } from './types'
import { getTasks } from './actions'

const initialState: TUserState = {
  todoList: {
    data: null,
    error: null,
    loading: false,
  },
}

const userSlice = createSlice({
  name: 'task',
  initialState,
  reducers: {},
  extraReducers: builder => {
    builder
      .addCase(getTasks.pending, state => {
        state.todoList.loading = true
        state.todoList.error = null
      })
      .addCase(getTasks.rejected, (state, action) => {
        state.todoList.loading = false
        state.todoList.error = action.payload as null
      })
      .addCase(getTasks.fulfilled, (state, action) => {
        state.todoList.loading = false
        state.todoList.error = null
        state.todoList.data = action.payload
      })
  },
})

const userSliceReducer = userSlice.reducer

export default userSliceReducer
