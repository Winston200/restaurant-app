import { useAuth } from '../../auth/AuthContext'
import './Home.css'

function Home() {
  const { admin, logout } = useAuth()
  const displayName =
    admin?.name || admin?.username || admin?.phone || `管理员 #${admin?.id ?? ''}`

  async function handleLogout() {
    await logout()
  }

  return (
    <main className="home">
      <h1 className="home__title">餐厅管理后台</h1>
      <p className="home__hint">已登录：{displayName}</p>
      <button type="button" className="home__logout" onClick={handleLogout}>
        退出登录
      </button>
    </main>
  )
}

export default Home
