import { createAsyncThunk } from '@reduxjs/toolkit'

import axiosInstance from 'libraries/axios'
import { getCookie, setCookie } from 'libraries/cookie'
import { showNotification, ToastVersions } from 'libraries/toastify'

import type { TSignInReq, TSignUpReq } from './types'

export const signIn = createAsyncThunk('auth/login', async (body: TSignInReq, { rejectWithValue }) => {
  try {
    const { data } = await axiosInstance.post('/auth/login', body)
    const rememberMe = getCookie('rememberMe')

    setCookie('token', data?.accessToken, rememberMe ? 15 : undefined)

    showNotification(ToastVersions.success, 'Login success')

    return data
  } catch (error: any) {
    showNotification(ToastVersions.error, error.message)

    return rejectWithValue(error.response.data)
  }
})

export const signUp = createAsyncThunk('auth/sign-up', async (body: TSignUpReq, { rejectWithValue }) => {
  try {
    const { data } = await axiosInstance.post('/users', body)

    showNotification(ToastVersions.success, 'SignUp success')

    return data
  } catch (error: any) {
    showNotification(ToastVersions.error, error.message)

    return rejectWithValue(error.response.data)
  }
})
