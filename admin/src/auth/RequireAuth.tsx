import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from './AuthContext'

export function RequireAuth() {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'bootstrapping') {
    return (
      <div className="auth-boot">
        <p>正在恢复登录状态…</p>
      </div>
    )
  }

  if (status !== 'authenticated') {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <Outlet />
}

export function GuestOnly() {
  const { status } = useAuth()

  if (status === 'bootstrapping') {
    return (
      <div className="auth-boot">
        <p>正在恢复登录状态…</p>
      </div>
    )
  }

  if (status === 'authenticated') {
    return <Navigate to="/admin" replace />
  }

  return <Outlet />
}
