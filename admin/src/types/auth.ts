export type AdminProfile = {
  id: string
  phone: string | null
  username?: string
  name?: string
}

export type TokenPair = {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  refresh_expires_in: number
  admin?: AdminProfile
}

export type ApiBody<T> = {
  code: number
  message: string
  data: T
}

export type LoginInput = {
  /** Backend field is username; accepts username or phone. */
  phone: string
  password: string
}
