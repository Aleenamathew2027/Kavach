import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import styles from './Login.module.css';

export default function Login() {
  const navigate = useNavigate();

  const [form,     setForm]     = useState({ email: '', password: '' });
  const [remember, setRemember] = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [showPwd,  setShowPwd]  = useState(false);

  /* Redirect if already logged in */
  useEffect(() => {
    if (localStorage.getItem('kavach_logged_in') === 'true') {
      navigate('/dashboard', { replace: true });
    }
  }, [navigate]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (error) setError('');
  };

  const validate = () => {
    if (!form.email.trim())               return 'Please enter your email address.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
                                          return 'Please enter a valid email address.';
    if (!form.password)                   return 'Please enter your password.';
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const err = validate();
    if (err) { setError(err); return; }

    setLoading(true);
    setError('');

    await new Promise((r) => setTimeout(r, 900));

    localStorage.setItem('kavach_logged_in', 'true');
    if (remember) localStorage.setItem('kavach_remember', 'true');
    navigate('/dashboard', { replace: true });
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
            <h1 className={styles.formTitle}>Sign In</h1>
            <p className={styles.formSubtitle}>Access your KAVACH security dashboard</p>
          </div>

          {error && (
            <div className={styles.errorBanner} role="alert">
              <span className={styles.errorIcon}>⚠</span>
              <span>{error}</span>
            </div>
          )}

          <form id="login-form" className={styles.form} onSubmit={handleSubmit} noValidate>

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
                <button type="button" className={styles.forgot}>Forgot password?</button>
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
                  Signing In…
                </span>
              ) : (
                <>
                  Sign In to KAVACH
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

          <div className={styles.demoBadge}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Demo mode — any valid email &amp; password will work
          </div>
        </div>
      </main>
    </div>
  );
}
