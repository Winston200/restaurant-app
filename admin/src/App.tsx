import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { GuestOnly, RequireAuth } from './auth/RequireAuth'
import Home from './pages/home/Home'
import Login from './pages/login/Login'
import './App.css'

function App() {
  return (
    <AuthProvider>
      <div className="app">
        <Routes>
          <Route path="/" element={<Navigate to="/admin" replace />} />

          <Route element={<GuestOnly />}>
            <Route path="/login" element={<Login />} />
          </Route>

          <Route path="/admin" element={<RequireAuth />}>
            <Route index element={<Home />} />
            <Route path="*" element={<Home />} />
          </Route>

          <Route path="*" element={<Navigate to="/admin" replace />} />
        </Routes>
      </div>
    </AuthProvider>
  )
}

export default App
