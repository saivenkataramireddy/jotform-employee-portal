import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

const API_BASE = 'http://localhost:5001/api';

/* ──────────────────────────────────────────
   Access Denied Screen
   ────────────────────────────────────────── */
const AccessDenied = ({ reason }) => (
  <div style={{
    minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'radial-gradient(ellipse at top, rgba(239,68,68,0.08) 0%, transparent 60%), var(--bg-base)',
    padding: '1.5rem',
  }}>
    <div style={{
      maxWidth: 420, width: '100%', textAlign: 'center',
      background: 'var(--glass)', border: '1px solid rgba(239,68,68,0.2)',
      borderRadius: 'var(--radius-xl)', padding: '3rem 2.5rem',
      boxShadow: '0 24px 60px rgba(0,0,0,0.6)',
      animation: 'fadeUp 0.5s ease',
    }}>
      <div style={{
        width: 72, height: 72, borderRadius: '50%',
        background: 'rgba(239,68,68,0.12)',
        border: '2px solid rgba(239,68,68,0.3)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '2rem', margin: '0 auto 1.5rem',
      }}>🔒</div>
      <h2 style={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.75rem' }}>
        Access Denied
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', lineHeight: 1.6, marginBottom: '2rem' }}>
        {reason || 'You are not authorized to access this portal.'}
      </p>
      <div style={{
        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)',
        borderRadius: 8, padding: '0.75rem 1rem',
        fontSize: '0.8rem', color: 'rgba(252,165,165,0.8)', lineHeight: 1.5,
      }}>
        Please contact your administrator or access this portal through the correct link provided to you.
      </div>
    </div>
  </div>
);

/* ──────────────────────────────────────────
   Loading Screen
   ────────────────────────────────────────── */
const LoadingScreen = ({ message = 'Authenticating...' }) => (
  <div style={{
    minHeight: '100vh', display: 'flex', flexDirection: 'column',
    alignItems: 'center', justifyContent: 'center', gap: '1rem',
    background: 'radial-gradient(ellipse at top, rgba(99,102,241,0.08) 0%, transparent 60%), var(--bg-base)',
  }}>
    <div style={{
      width: 48, height: 48, border: '3px solid rgba(99,102,241,0.2)',
      borderTopColor: 'var(--primary)', borderRadius: '50%',
      animation: 'spin 0.8s linear infinite',
    }} />
    <p style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>{message}</p>
  </div>
);

/* ──────────────────────────────────────────
   Main Dashboard Component
   ────────────────────────────────────────── */
const Dashboard = () => {
  const [searchParams] = useSearchParams();

  const [status, setStatus] = useState('loading'); // 'loading' | 'denied' | 'ready'
  const [deniedReason, setDeniedReason] = useState('');
  const [loadingMsg, setLoadingMsg] = useState('Authenticating...');
  const [employee, setEmployee] = useState(null);
  const [forms, setForms] = useState([]);
  const [loadingForms, setLoadingForms] = useState(false);
  const [selectedForm, setSelectedForm] = useState(null);
  const [openingForm, setOpeningForm] = useState(null);

  /* ── Auth on mount ── */
  useEffect(() => {
    authenticate();
  }, []);

  const deny = (reason) => {
    setDeniedReason(reason);
    setStatus('denied');
  };

  const decodeToken = (token) => {
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const p = JSON.parse(decodeURIComponent(
        atob(b64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
      ));
      return {
        employee_id: p.employee_id, full_name: p.full_name, division_id: p.division_id,
        division_name: p.division_name, designation: p.designation, hq: p.hq
      };
    } catch { return null; }
  };

  const persist = (token, emp) => {
    localStorage.setItem('token', token);
    localStorage.setItem('isLoggedIn', 'true');
    localStorage.setItem('employeeId', emp.employee_id);
    localStorage.setItem('employee_data', JSON.stringify(emp));
  };

  const authenticate = async () => {
    // 1. JWT token in URL (from /auto-login redirect)
    const urlToken = searchParams.get('token');
    if (urlToken) {
      setLoadingMsg('Validating session token...');
      const emp = decodeToken(urlToken);
      if (emp) {
        persist(urlToken, emp);
        window.history.replaceState({}, '', '/dashboard');
        setEmployee(emp);
        await fetchForms(emp.employee_id, urlToken);
        setStatus('ready');
        return;
      } else {
        deny('The session token is invalid or has expired.');
        return;
      }
    }

    // 2. Direct URL params: ?employeeId=&division=
    const urlEmpId = searchParams.get('employeeId');
    const urlDiv = searchParams.get('division');

    if (urlEmpId && urlDiv) {
      setLoadingMsg(`Authenticating ${urlEmpId}...`);
      try {
        const res = await fetch(`${API_BASE}/direct-login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ employeeId: urlEmpId, division: urlDiv }),
        });
        const data = await res.json();

        if (res.ok && data.success) {
          persist(data.token, data.employee);
          window.history.replaceState({}, '', '/dashboard');
          setEmployee(data.employee);
          await fetchForms(data.employee.employee_id, data.token);
          setStatus('ready');
        } else {
          deny(
            data.message === 'Invalid Employee ID or Division'
              ? `No employee found with ID "${urlEmpId}" in the "${urlDiv}" division. Please verify your access link.`
              : (data.message || 'Authentication failed. Invalid credentials.')
          );
        }
      } catch {
        deny('Unable to reach the authentication server. Please try again later.');
      }
      return;
    }

    // 3. Existing localStorage session
    const token = localStorage.getItem('token');
    const raw = localStorage.getItem('employee_data');
    if (token && raw) {
      try {
        setLoadingMsg('Restoring session...');
        const emp = JSON.parse(raw);
        setEmployee(emp);
        await fetchForms(emp.employee_id, token);
        setStatus('ready');
        return;
      } catch { /* fall through */ }
    }

    // 4. No credentials at all
    deny('No valid credentials were provided. Please access this portal through the link sent to you.');
  };

  const fetchForms = async (empId, token) => {
    setLoadingForms(true);
    try {
      const res = await fetch(`${API_BASE}/forms/${empId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) {
        deny('Your session has expired. Please use the access link sent to you.');
        return;
      }
      const data = await res.json();
      if (data.success) setForms(data.forms);
    } catch { /* silently fail — forms just stay empty */ }
    finally { setLoadingForms(false); }
  };

  const handleLogout = () => {
    localStorage.clear();
    // Without a login page, just show access denied so user knows they are logged out
    deny('You have been logged out. Please use your access link to log back in.');
  };

  const openForm = async (form) => {
    setOpeningForm(form.id);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/open-form/${form.id}/${employee.employee_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok && data.success) setSelectedForm(data.form);
    } catch { /* silently fail */ }
    finally { setOpeningForm(null); }
  };

  /* ── Render states ── */
  if (status === 'loading') return <LoadingScreen message={loadingMsg} />;
  if (status === 'denied') return <AccessDenied reason={deniedReason} />;

  const initials = employee?.full_name
    ? employee.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase()
    : 'U';

  const today = new Date().toLocaleDateString('en-US', {
    weekday: 'long', month: 'long', day: 'numeric', year: 'numeric',
  });

  return (
    <>
      <div className="portal-layout">
        {/* Forms section */}
        <div className="forms-section">
          <div className="forms-section-header">
            <div className="forms-section-title">
              <span className="section-icon">📋</span>
              Available Forms
            </div>
            <span className="forms-badge">
              {forms.length} form{forms.length !== 1 ? 's' : ''}
            </span>
          </div>

          {loadingForms ? (
            <div className="loading-spinner-wrap">
              <div className="spinner-lg" />
              <p>Loading forms...</p>
            </div>
          ) : forms.length === 0 ? (
            <div className="empty-forms">
              <span className="empty-forms-icon">📭</span>
              <h3>No Forms Available</h3>
              <p>There are no forms assigned to your division yet.</p>
            </div>
          ) : (
            <div className="forms-list">
              {forms.map((form, i) => (
                <div
                  className="form-card-emp"
                  key={form.id}
                  style={{ animationDelay: `${i * 0.06}s` }}
                >
                  <div className="form-card-icon-emp">📄</div>
                  <div className="form-card-body">
                    <div className="form-card-name">{form.form_name}</div>
                    <span className="form-card-division">🏢 {form.division_name}</span>
                  </div>
                  <button
                    className="btn-open-form"
                    onClick={() => openForm(form)}
                    disabled={openingForm === form.id}
                  >
                    {openingForm === form.id
                      ? <><div className="spinner" /> Opening...</>
                      : <><span>Open Form</span> <span>↗</span></>
                    }
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Form modal ── */}
      {selectedForm && (
        <div
          className="modal-overlay"
          onClick={(e) => { if (e.target === e.currentTarget) setSelectedForm(null); }}
        >
          <div className="modal-box">
            <div className="modal-header">
              <div className="modal-title">📄 {selectedForm.form_name}</div>
              <button className="btn-modal-close" onClick={() => setSelectedForm(null)}>✕</button>
            </div>
            <div className="modal-iframe-wrap">
              <iframe src={selectedForm.sso_url} title={selectedForm.form_name} allowFullScreen />
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default Dashboard;
