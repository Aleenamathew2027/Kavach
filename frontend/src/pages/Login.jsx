import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, setAuth, getToken, getRole } from '../services/api';
import styles from './Login.module.css';

export default function Login() {
  const navigate = useNavigate();

  const [mode, setMode] = useState('account'); // 'account' | 'guardian'
  const [form, setForm] = useState({ email: '', password: '' });
  const [guardianCode, setGuardianCode] = useState('');
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  /* Redirect if already logged in */
  useEffect(() => {
    const token = getToken();
    const role = getRole();
    if (token) {
      if (role === 'admin') navigate('/admin/dashboard', { replace: true });
      else if (role === 'guardian') navigate('/guardian/dashboard', { replace: true });
      else navigate('/user/dashboard', { replace: true });
    }
  }, [navigate]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (error) setError('');
  };

  const handleGuardianCodeChange = (e) => {
    const val = e.target.value.replace(/\D/g, '').slice(0, 6);
    setGuardianCode(val);
    if (error) setError('');
  };

  const validate = () => {
    if (mode === 'account') {
      if (!form.email.trim()) return 'Please enter your email address.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
        return 'Please enter a valid email address.';
      }
      if (!form.password) return 'Please enter your password.';
    } else {
      if (!guardianCode || guardianCode.length !== 6) {
        return 'Please enter a valid 6-digit guardian access code.';
      }
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const err = validate();
    if (err) {
      setError(err);
      return;
    }

    setLoading(true);
    setError('');

    try {
      if (mode === 'account') {
        const data = await api.login({
          email: form.email.trim().toLowerCase(),
          password: form.password,
        });

        setAuth({ token: data.access_token, role: data.role || 'user' });

        if (data.role === 'admin') {
          navigate('/admin/dashboard', { replace: true });
        } else {
          navigate('/user/dashboard', { replace: true });
        }
      } else {
        // Guardian Mode
        const data = await api.verifyGuardianCode({ code: guardianCode });

        setAuth({ token: data.access_token, role: 'guardian' });
        navigate('/guardian/dashboard', { replace: true });
      }
    } catch (err) {
      setError(err.message || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.page}>
      {/* ── Left panel ── */}
      <aside className={styles.leftPanel}>
        <div className={styles.leftInner}>
          <Link to="/" className={styles.logo}>
            <span className={styles.logoIcon}>⚡</span>
            <span className={styles.logoText}>KAVACH</span>
          </Link>

          <div className={styles.leftContent}>
            <h2 className={styles.panelHeading}>
              Welcome<br />
              <span className={styles.panelAccent}>Back</span>
            </h2>
            <p className={styles.panelSubtext}>
              Your AI guardian has been keeping watch. Log in to check your security status.
            </p>

            <div className={styles.statusCard}>
              <div className={styles.statusDot} />
              <div>
                <div className={styles.statusTitle}>System Status</div>
                <div className={styles.statusValue}>All Modules Active</div>
              </div>
            </div>

            <div className={styles.statsRow}>
              <div className={styles.statItem}>
                <span className={styles.statVal}>6+</span>
                <span className={styles.statKey}>AI Modules</span>
              </div>
              <div className={styles.statDivider} />
              <div className={styles.statItem}>
                <span className={styles.statVal}>24/7</span>
                <span className={styles.statKey}>Monitoring</span>
              </div>
              <div className={styles.statDivider} />
              <div className={styles.statItem}>
                <span className={styles.statVal}>AI</span>
                <span className={styles.statKey}>Powered</span>
              </div>
            </div>
          </div>

          <div className={styles.decorRing1} aria-hidden="true" />
          <div className={styles.decorRing2} aria-hidden="true" />
        </div>
      </aside>

      {/* ── Right panel ── */}
      <main className={styles.rightPanel}>
        <div className={styles.formWrap}>
          {/* Mobile logo */}
          <Link to="/" className={`${styles.logo} ${styles.mobileLogo}`}>
            <span className={styles.logoIcon}>⚡</span>
            <span className={styles.logoText}>KAVACH</span>
          </Link>

          <div className={styles.formHeader}>
            <h1 className={styles.formTitle}>
              {mode === 'account' ? 'Sign In' : 'Guardian Access'}
            </h1>
            <p className={styles.formSubtitle}>
              {mode === 'account'
                ? 'Access your KAVACH security dashboard'
                : 'Enter your 6-digit access code to view guarded safety alerts'}
            </p>
          </div>

          {/* Mode Switch Tabs */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', background: 'rgba(255,255,255,0.03)', padding: '4px', borderRadius: '10px', border: '1px solid rgba(0, 255, 136, 0.1)' }}>
            <button
              type="button"
              onClick={() => { setMode('account'); setError(''); }}
              style={{
                flex: 1,
                padding: '8px 12px',
                border: 'none',
                borderRadius: '7px',
                background: mode === 'account' ? 'rgba(0, 255, 136, 0.15)' : 'transparent',
                color: mode === 'account' ? '#00ff88' : '#64748b',
                fontWeight: 600,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              Account Login
            </button>
            <button
              type="button"
              onClick={() => { setMode('guardian'); setError(''); }}
              style={{
                flex: 1,
                padding: '8px 12px',
                border: 'none',
                borderRadius: '7px',
                background: mode === 'guardian' ? 'rgba(0, 255, 136, 0.15)' : 'transparent',
                color: mode === 'guardian' ? '#00ff88' : '#64748b',
                fontWeight: 600,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              Guardian Code
            </button>
          </div>

          {error && (
            <div className={styles.errorBanner} role="alert">
              <span className={styles.errorIcon}>⚠</span>
              <span>{error}</span>
            </div>
          )}

          <form id="login-form" className={styles.form} onSubmit={handleSubmit} noValidate>
            {mode === 'account' ? (
              <>
                {/* Email */}
                <div className={styles.field}>
                  <label htmlFor="login-email" className={styles.label}>Email Address</label>
                  <div className={styles.inputWrap}>
                    <span className={styles.inputPrefix}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                    </span>
                    <input
                      id="login-email"
                      type="email"
                      name="email"
                      className={styles.input}
                      placeholder="you@example.com"
                      value={form.email}
                      onChange={handleChange}
                      autoComplete="email"
                      aria-required="true"
                    />
                  </div>
                </div>

                {/* Password */}
                <div className={styles.field}>
                  <div className={styles.labelRow}>
                    <label htmlFor="login-password" className={styles.label}>Password</label>
                  </div>
                  <div className={styles.inputWrap}>
                    <span className={styles.inputPrefix}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </span>
                    <input
                      id="login-password"
                      type={showPwd ? 'text' : 'password'}
                      name="password"
                      className={styles.input}
                      placeholder="Enter your password"
                      value={form.password}
                      onChange={handleChange}
                      autoComplete="current-password"
                      aria-required="true"
                    />
                    <button
                      type="button"
                      className={styles.eye}
                      onClick={() => setShowPwd((v) => !v)}
                      aria-label={showPwd ? 'Hide password' : 'Show password'}
                    >
                      {showPwd
                        ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                        : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                      }
                    </button>
                  </div>
                </div>

                {/* Remember me */}
                <label className={styles.rememberLabel} htmlFor="remember-me">
                  <input
                    id="remember-me"
                    type="checkbox"
                    checked={remember}
                    onChange={(e) => setRemember(e.target.checked)}
                    className={styles.checkbox}
                  />
                  <span className={styles.rememberText}>Remember me on this device</span>
                </label>
              </>
            ) : (
              /* Guardian 6-Digit Code Mode */
              <div className={styles.field}>
                <label htmlFor="guardian-code" className={styles.label}>6-Digit Guardian Code</label>
                <div className={styles.inputWrap}>
                  <span className={styles.inputPrefix}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  </span>
                  <input
                    id="guardian-code"
                    type="text"
                    name="guardianCode"
                    className={styles.input}
                    placeholder="Enter 6-digit code"
                    value={guardianCode}
                    onChange={handleGuardianCodeChange}
                    maxLength={6}
                    style={{ letterSpacing: '4px', fontSize: '18px', fontWeight: 'bold' }}
                    autoComplete="off"
                    aria-required="true"
                  />
                </div>
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit"
              type="submit"
              className={styles.submitBtn}
              disabled={loading}
              aria-busy={loading}
            >
              {loading ? (
                <span className={styles.loadingRow}>
                  <span className={styles.spinner} aria-hidden="true" />
                  {mode === 'account' ? 'Signing In…' : 'Verifying Code…'}
                </span>
              ) : (
                <>
                  {mode === 'account' ? 'Sign In to KAVACH' : 'Access Guardian Portal'}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </>
              )}
            </button>
          </form>

          <p className={styles.registerPrompt}>
            Don't have an account?{' '}
            <Link to="/register" className={styles.registerLink} id="go-to-register">
              Create Account
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}
