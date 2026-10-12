import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../auth/AuthContext'
import { ApiError } from '../../services/authApi'
import './Login.css'

function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [phone, setPhone] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)

    if (!phone.trim() || !password) {
      setError('请输入手机号和密码')
      return
    }

    setSubmitting(true)
    try {
      await login({ phone, password })
      navigate('/admin', { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('登录失败，请稍后重试')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login">
      <form className="login__form" onSubmit={handleSubmit} noValidate>
        <h1 className="login__title">餐厅管理后台</h1>
        <p className="login__subtitle">管理员登录</p>

        <label className="login__field">
          <span>手机号</span>
          <input
            type="text"
            name="phone"
            autoComplete="username"
            inputMode="tel"
            placeholder="手机号或用户名"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            disabled={submitting}
          />
        </label>

        <label className="login__field">
          <span>密码</span>
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            placeholder="请输入密码"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
          />
        </label>

        {error ? <p className="login__error" role="alert">{error}</p> : null}

        <button className="login__submit" type="submit" disabled={submitting}>
          {submitting ? '登录中…' : '登录'}
        </button>
      </form>
    </main>
  )
}

export default Login
