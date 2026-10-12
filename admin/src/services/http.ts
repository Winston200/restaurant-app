import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'
import {
  clearTokens,
  getAccessToken,
  getRefreshToken,
  persistTokenPair,
} from '../auth/tokenStore'
import type { ApiBody, TokenPair } from '../types/auth'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? ''

type RetriableConfig = InternalAxiosRequestConfig & {
  _retry?: boolean
}

let refreshPromise: Promise<string> | null = null
let onAuthFailure: (() => void) | null = null

/** AuthProvider registers this to clear React state and navigate to /login. */
export function setAuthFailureHandler(handler: (() => void) | null): void {
  onAuthFailure = handler
}

function isAuthPath(url: string | undefined): boolean {
  if (!url) return false
  return (
    url.includes('/admin/login') ||
    url.includes('/admin/refresh') ||
    url.includes('/admin/logout')
  )
}

/** Bare client without 401→refresh to avoid interceptor loops. */
const bareClient: AxiosInstance = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

apiClient.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

async function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const refreshToken = getRefreshToken()
      if (!refreshToken) {
        throw new Error('missing refresh token')
      }

      const { data } = await bareClient.post<ApiBody<TokenPair>>(
        '/api/admin/refresh',
        { refresh_token: refreshToken },
      )

      if (data.code !== 0 || !data.data?.access_token || !data.data?.refresh_token) {
        throw new Error(data.message || 'refresh failed')
      }

      persistTokenPair(data.data)
      return data.data.access_token
    })().finally(() => {
      refreshPromise = null
    })
  }

  return refreshPromise
}

function handleAuthFailure(): void {
  clearTokens()
  onAuthFailure?.()
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const config = error.config as RetriableConfig | undefined
    const status = error.response?.status

    if (!config || status !== 401 || isAuthPath(config.url) || config._retry) {
      return Promise.reject(error)
    }

    if (!getRefreshToken()) {
      handleAuthFailure()
      return Promise.reject(error)
    }

    try {
      const accessToken = await refreshAccessToken()
      config._retry = true
      config.headers.Authorization = `Bearer ${accessToken}`
      return apiClient.request(config)
    } catch {
      handleAuthFailure()
      return Promise.reject(error)
    }
  },
)

export { bareClient, refreshAccessToken }
