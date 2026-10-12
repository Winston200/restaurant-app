import {
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useState,
  type ReactNode,
} from 'react'
import { useNavigate } from 'react-router-dom'
import {
  fetchMe,
  login as loginRequest,
  logout as logoutRequest,
  restoreSession,
} from '../services/authApi'
import { setAuthFailureHandler } from '../services/http'
import type { AdminProfile, LoginInput } from '../types/auth'
import { clearTokens } from './tokenStore'

type AuthStatus = 'bootstrapping' | 'authenticated' | 'anonymous'

type AuthContextValue = {
  status: AuthStatus
  admin: AdminProfile | null
  login: (input: LoginInput) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const [status, setStatus] = useState<AuthStatus>('bootstrapping')
  const [admin, setAdmin] = useState<AdminProfile | null>(null)

  const handleAuthFailure = useEffectEvent(() => {
    clearTokens()
    setAdmin(null)
    setStatus('anonymous')
    navigate('/login', { replace: true })
  })

  useEffect(() => {
    setAuthFailureHandler(() => {
      handleAuthFailure()
    })
    return () => setAuthFailureHandler(null)
  }, [])

  useEffect(() => {
    let cancelled = false

    ;(async () => {
      const profile = await restoreSession()
      if (cancelled) return

      if (profile) {
        setAdmin(profile)
        setStatus('authenticated')
      } else {
        setAdmin(null)
        setStatus('anonymous')
      }
    })()

    return () => {
      cancelled = true
    }
  }, [])

  async function login(input: LoginInput): Promise<void> {
    const pair = await loginRequest(input)
    const profile =
      (await fetchMe().catch(() => null)) ??
      pair.admin ?? {
        id: '',
        phone: input.phone.trim(),
      }

    setAdmin(profile)
    setStatus('authenticated')
  }

  async function logout(): Promise<void> {
    await logoutRequest()
    setAdmin(null)
    setStatus('anonymous')
    navigate('/login', { replace: true })
  }

  return (
    <AuthContext.Provider value={{ status, admin, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return ctx
}
