import { createAsyncThunk } from '@reduxjs/toolkit'

import axiosInstance from 'libraries/axios'
import { ToastVersions, showNotification } from 'libraries/toastify'

export const getProfileData = createAsyncThunk('users/profile', async () => {
  try {
    const { data } = await axiosInstance.get(`/users`)

    return data
  } catch (error: any) {
    const errorMessage = error.response.data.message

    showNotification(ToastVersions.error, errorMessage)
  }
})
