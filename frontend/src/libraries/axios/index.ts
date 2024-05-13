import axios, { type AxiosRequestConfig } from 'axios'

import { getCookie } from 'libraries/cookie'

const defaultOptions = {
  baseURL: process.env.REACT_APP_BASE_URL,
}

const axiosInstance = axios.create(defaultOptions)

axiosInstance.interceptors.request.use(
  async (config: AxiosRequestConfig) => {
    const selectedLanguage = localStorage.getItem('i18nextLng') || 'en'

    const accessToken = getCookie('token')

    config.headers = {
      'x-custom-lang': selectedLanguage,
      Authorization: `Bearer ${accessToken}`,
      'ngrok-skip-browser-warning': 'true',
    }

    return config
  },

  error => Promise.reject(error)
)

export default axiosInstance
