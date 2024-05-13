import { createAsyncThunk } from '@reduxjs/toolkit'

import axiosInstance from 'libraries/axios'
import { ToastVersions, showNotification } from 'libraries/toastify'

import type { TSendTasks, TTasks } from './types'

export const getTasks = createAsyncThunk('get/tasks', async () => {
  try {
    const { data } = await axiosInstance.get(`/tasks?page=1&pageSize=999`)

    return data
  } catch (error: any) {
    if (error.response.data.statusCode === 401) {
      return (location.href = '/')
    }
    showNotification(ToastVersions.error, error.message)
  }
})

export const sendTasks = createAsyncThunk('send/tasks', async (body: TSendTasks, { dispatch }) => {
  try {
    const { data } = await axiosInstance.post('/tasks', body)
    dispatch(getTasks())

    return data
  } catch (error: any) {
    showNotification(ToastVersions.error, error.message)
  }
})

export const editTasks = createAsyncThunk(
  'edit/tasks',
  async (body: { id: number; editedTask: TTasks | unknown }, { dispatch }) => {
    try {
      const { id, editedTask } = body

      const { data } = await axiosInstance.patch(`/tasks/${id}`, editedTask)

      dispatch(getTasks())
      showNotification(ToastVersions.info, 'Edited successfully')

      return data
    } catch (error: any) {
      showNotification(ToastVersions.error, error.message)
    }
  }
)

export const deleteTasks = createAsyncThunk('delete/tasks', async (id: number, { dispatch }) => {
  try {
    const { data } = await axiosInstance.delete(`/tasks/${id}`)

    dispatch(getTasks())
    showNotification(ToastVersions.info, 'Deleted successfully')

    return data
  } catch (error: any) {
    showNotification(ToastVersions.error, error.message)
  }
})
