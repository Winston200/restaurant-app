import axios from 'axios'
import {
  clearTokens,
  getRefreshToken,
  persistTokenPair,
} from '../auth/tokenStore'
import type { AdminProfile, ApiBody, LoginInput, TokenPair } from '../types/auth'
import { apiClient, bareClient, refreshAccessToken } from './http'

export class ApiError extends Error {
  status: number
  code: number

  constructor(message: string, status: number, code: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

function toApiError(error: unknown, fallback: string): ApiError {
  if (axios.isAxiosError(error)) {
    const body = error.response?.data as ApiBody<unknown> | undefined
    return new ApiError(
      body?.message || error.message || fallback,
      error.response?.status ?? 0,
      body?.code ?? 0,
    )
  }
  if (error instanceof Error) {
    return new ApiError(error.message, 0, 0)
  }
  return new ApiError(fallback, 0, 0)
}

export async function login(input: LoginInput): Promise<TokenPair> {
  try {
    const { data } = await bareClient.post<ApiBody<TokenPair>>('/api/admin/login', {
      username: input.phone.trim(),
      password: input.password,
    })

    if (data.code !== 0 || !data.data?.access_token || !data.data?.refresh_token) {
      throw new ApiError(data.message || '登录失败', 200, data.code)
    }

    persistTokenPair(data.data)
    return data.data
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw toApiError(error, '登录失败')
  }
}

export async function logout(): Promise<void> {
  const refreshToken = getRefreshToken()
  try {
    if (refreshToken) {
      await bareClient.post<ApiBody<{ logged_out: boolean }>>('/api/admin/logout', {
        refresh_token: refreshToken,
      })
    }
  } catch {
    // Still clear local session even if the network call fails.
  } finally {
    clearTokens()
  }
}

export async function restoreSession(): Promise<AdminProfile | null> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) {
    clearTokens()
    return null
  }

  try {
    await refreshAccessToken()
    return await fetchMe()
  } catch {
    clearTokens()
    return null
  }
}

export async function fetchMe(): Promise<AdminProfile> {
  try {
    const { data } = await apiClient.get<
      ApiBody<{
        id: string
        username: string
        name: string
        phone: string | null
        status: number
      }>
    >('/api/admin/me')

    if (data.code !== 0 || !data.data) {
      throw new ApiError(data.message || '获取用户信息失败', 200, data.code)
    }

    return {
      id: data.data.id,
      phone: data.data.phone,
      username: data.data.username,
      name: data.data.name,
    }
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw toApiError(error, '获取用户信息失败')
  }
}
