import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const API_BASE = 'http://localhost:5001/api';

const Login = () => {
  const [employeeId, setEmployeeId] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/employee-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ employee_id: employeeId, password }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('employeeId', data.employee.employee_id);
        localStorage.setItem('employee_data', JSON.stringify(data.employee));
        navigate('/dashboard');
      } else {
        setError(data.message || 'Invalid credentials');
      }
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="emp-login-page">
      <div className="emp-login-card">
        <div className="emp-login-icon">🏢</div>

        <div className="emp-login-heading">
          <h2>Employee Portal</h2>
          <p>Sign in to access your forms and dashboard</p>
        </div>

        {error && (
          <div className="emp-error">
            <span>⚠️</span><span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div className="input-group">
            <label htmlFor="emp-id">Employee ID</label>
            <div className="emp-input-wrap">
              <span className="emp-input-icon">🪪</span>
              <input
                id="emp-id"
                className="emp-input"
                type="text"
                value={employeeId}
                onChange={(e) => setEmployeeId(e.target.value)}
                placeholder="Enter your Employee ID"
                required
              />
            </div>
          </div>

          <div className="input-group">
            <label htmlFor="emp-pwd">Password</label>
            <div className="emp-input-wrap" style={{ position: 'relative' }}>
              <span className="emp-input-icon">🔒</span>
              <input
                id="emp-pwd"
                className="emp-input"
                type={showPwd ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPwd(!showPwd)}
                style={{
                  position: 'absolute', right: '1rem', top: '50%',
                  transform: 'translateY(-50%)', background: 'none',
                  border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: '1rem'
                }}
              >
                {showPwd ? '🙈' : '👁️'}
              </button>
            </div>
          </div>

          <button type="submit" className="emp-login-btn" disabled={loading}>
            {loading
              ? <><div className="spinner" /><span>Signing in...</span></>
              : <span>Sign In →</span>
            }
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;
