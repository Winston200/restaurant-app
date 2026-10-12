/**
 * Token storage policy for this SPA (JSON body tokens from API):
 * - Access Token: in-memory only (short-lived, not readable from storage).
 * - Refresh Token: sessionStorage via this module only (survives reload in the
 *   same tab; cleared when the tab closes). Business pages must not import this.
 * - Never put tokens in the URL or console.log.
 *
 * Ideal long-term is httpOnly Secure cookies set by the API; until then this
 * keeps Refresh out of ordinary app code and Access out of persistent storage.
 */

const REFRESH_KEY = 'restaurant.admin.refresh'

let accessToken: string | null = null

export function getAccessToken(): string | null {
  return accessToken
}

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function getRefreshToken(): string | null {
  try {
    return sessionStorage.getItem(REFRESH_KEY)
  } catch {
    return null
  }
}

export function setRefreshToken(token: string | null): void {
  try {
    if (token === null) {
      sessionStorage.removeItem(REFRESH_KEY)
    } else {
      sessionStorage.setItem(REFRESH_KEY, token)
    }
  } catch {
    // Private mode / blocked storage — ignore; session will not survive reload.
  }
}

export function persistTokenPair(pair: {
  access_token: string
  refresh_token: string
}): void {
  setAccessToken(pair.access_token)
  setRefreshToken(pair.refresh_token)
}

export function clearTokens(): void {
  setAccessToken(null)
  setRefreshToken(null)
}

export function hasRefreshToken(): boolean {
  return Boolean(getRefreshToken())
}
