import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import GoogleSignInButton from '../components/GoogleSignInButton';
import styles from './Register.module.css';

/* ── Password strength helper ── */
function getPasswordStrength(pwd) {
  if (!pwd) return { score: 0, label: '', color: 'transparent', width: '0%' };
  let score = 0;
  if (pwd.length >= 8)          score++;
  if (/[A-Z]/.test(pwd))        score++;
  if (/[0-9]/.test(pwd))        score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;
  const levels = [
    { label: 'Very Weak', color: '#ef4444', width: '20%'  },
    { label: 'Weak',      color: '#f97316', width: '40%'  },
    { label: 'Fair',      color: '#eab308', width: '60%'  },
    { label: 'Strong',    color: '#22c55e', width: '80%'  },
    { label: 'Very Strong', color: '#10b981', width: '100%' },
  ];
  return { score, ...levels[score] };
}

/* ── Left-panel feature list ── */
const panelFeatures = [
  { icon: '🛡️', text: 'AI-powered scam & phishing detection' },
  { icon: '🎙️', text: 'Deepfake voice call analysis' },
  { icon: '🔗', text: 'Malicious link & document scanner' },
  { icon: '💳', text: 'Suspicious payment request alerts' },
  { icon: '⚡', text: 'Real-time threat monitoring' },
];

export default function Register() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    full_name:       '',
    email:           '',
    password:        '',
    confirmPassword: '',
  });
  const [errors,      setErrors]      = useState({});
  const [loading,     setLoading]     = useState(false);
  const [apiError,    setApiError]    = useState('');
  const [isNetworkErr, setIsNetworkErr] = useState(false);
  const [success,     setSuccess]     = useState(false);
  const [showPwd,     setShowPwd]     = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const errorTimer = useRef(null);

  /* Auto-clear error after 10 seconds */
  const showError = useCallback((msg, isNetwork = false) => {
    setApiError(msg);
    setIsNetworkErr(isNetwork);
    clearTimeout(errorTimer.current);
    errorTimer.current = setTimeout(() => {
      setApiError('');
      setIsNetworkErr(false);
    }, 10000);
  }, []);

  const dismissError = () => {
    clearTimeout(errorTimer.current);
    setApiError('');
    setIsNetworkErr(false);
  };

  /* Cleanup timer on unmount */
  useEffect(() => () => clearTimeout(errorTimer.current), []);

  /* Redirect if already logged in */
  useEffect(() => {
    if (localStorage.getItem('kavach_logged_in') === 'true') {
      navigate('/dashboard', { replace: true });
    }
  }, [navigate]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (errors[name]) setErrors((prev) => ({ ...prev, [name]: '' }));
    if (apiError)     dismissError();
  };

  /* ── Validation ── */
  const validate = () => {
    const errs = {};
    const nameTrimmed = form.full_name.trim();
    if (!nameTrimmed) {
      errs.full_name = 'Full name is required.';
    } else if (nameTrimmed.length < 2) {
      errs.full_name = 'Name must be at least 2 characters.';
    } else if (!/^[A-Za-z\s]+$/.test(nameTrimmed)) {
      errs.full_name = 'Name must contain only letters and spaces (no numbers or symbols like @, #, $).';
    }

    if (!form.email.trim())
      errs.email = 'Email address is required.';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      errs.email = 'Please enter a valid email address.';

    if (!form.password)
      errs.password = 'Password is required.';
    else if (form.password.length < 6)
      errs.password = 'Password must be at least 6 characters.';

    if (!form.confirmPassword)
      errs.confirmPassword = 'Please confirm your password.';
    else if (form.password !== form.confirmPassword)
      errs.confirmPassword = 'Passwords do not match.';

    return errs;
  };

  const strength = getPasswordStrength(form.password);

  /* ── Submit ── */
  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationErrors = validate();
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    setLoading(true);
    setApiError('');

    try {
      await api.register({
        full_name: form.full_name.trim(),
        email: form.email.trim().toLowerCase(),
        password: form.password,
      });

      setSuccess(true);
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      const isNetwork = err.isNetwork || err.status === 0;
      showError(err.message || 'Registration failed. Please try again.', isNetwork);
    } finally {
      setLoading(false);
    }
  };

  /* ── Success screen ── */
  if (success) {
    return (
      <div className={styles.page}>
        <div className={styles.successOverlay}>
          <div className={styles.successCard}>
            <div className={styles.successRing} />
            <div className={styles.successIconWrap}>
              <span className={styles.successIcon}>✓</span>
            </div>
            <h2 className={styles.successTitle}>Registration Successful!</h2>
            <p className={styles.successDesc}>
              Registration successful. Redirecting you to login…
            </p>
            <div className={styles.successBar}>
              <div className={styles.successFill} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  /* ── Main ── */
  return (
    <div className={styles.page}>
      {/* ── Left panel ── */}
      <aside className={styles.leftPanel}>
        <div className={styles.leftInner}>
          {/* Logo */}
          <Link to="/" className={styles.logo}>
            <span className={styles.logoIcon}>⚡</span>
            <span className={styles.logoText}>KAVACH</span>
          </Link>

          <div className={styles.leftContent}>
            <h2 className={styles.panelHeading}>
              Guard Your<br />
              <span className={styles.panelAccent}>Digital World</span>
            </h2>
            <p className={styles.panelSubtext}>
              Join thousands of users protected by KAVACH's AI security engine.
            </p>

            <ul className={styles.featureList}>
              {panelFeatures.map((f) => (
                <li key={f.text} className={styles.featureItem}>
                  <span className={styles.featureIcon}>{f.icon}</span>
                  <span className={styles.featureText}>{f.text}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Decorative rings */}
          <div className={styles.decorRing1} aria-hidden="true" />
          <div className={styles.decorRing2} aria-hidden="true" />
          <div className={styles.decorRing3} aria-hidden="true" />
        </div>
      </aside>

      {/* ── Right panel (form) ── */}
      <main className={styles.rightPanel}>
        <div className={styles.formWrap}>
          {/* Mobile logo */}
          <Link to="/" className={`${styles.logo} ${styles.mobileLogo}`}>
            <span className={styles.logoIcon}>⚡</span>
            <span className={styles.logoText}>KAVACH</span>
          </Link>

          <div className={styles.formHeader}>
            <h1 className={styles.formTitle}>Create Account</h1>
            <p className={styles.formSubtitle}>
              Start your AI-powered security journey today
            </p>
          </div>

          {/* API error */}
          {apiError && (
            <div className={styles.errorBanner} role="alert" aria-live="assertive">
              <div className={styles.errorTop}>
                <span className={styles.errorIcon}>⚠</span>
                <span className={styles.errorMsg}>{apiError}</span>
                <button
                  type="button"
                  className={styles.errorClose}
                  onClick={dismissError}
                  aria-label="Dismiss error"
                >
                  ✕
                </button>
              </div>
              {isNetworkErr && (
                <div className={styles.errorHelp}>
                  <p className={styles.errorHelpTitle}>Start the backend with:</p>
                  <code className={styles.errorCmd}>
                    cd backend &amp;&amp; .\venv\Scripts\activate &amp;&amp; uvicorn main:app --reload
                  </code>
                </div>
              )}
              <div className={styles.errorProgress} />
            </div>
          )}

          <form id="register-form" className={styles.form} onSubmit={handleSubmit} noValidate>

            {/* Full Name */}
            <div className={styles.field}>
              <label htmlFor="reg-name" className={styles.label}>Full Name</label>
              <div className={`${styles.inputWrap} ${errors.full_name ? styles.hasError : ''}`}>
                <span className={styles.inputPrefix}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </span>
                <input
                  id="reg-name"
                  type="text"
                  name="full_name"
                  className={styles.input}
                  placeholder="Enter your full name"
                  value={form.full_name}
                  onChange={handleChange}
                  autoComplete="name"
                  aria-required="true"
                  aria-describedby={errors.full_name ? 'err-name' : undefined}
                />
              </div>
              {errors.full_name && (
                <span id="err-name" className={styles.fieldError} role="alert">
                  {errors.full_name}
                </span>
              )}
            </div>

            {/* Email */}
            <div className={styles.field}>
              <label htmlFor="reg-email" className={styles.label}>Email Address</label>
              <div className={`${styles.inputWrap} ${errors.email ? styles.hasError : ''}`}>
                <span className={styles.inputPrefix}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                </span>
                <input
                  id="reg-email"
                  type="email"
                  name="email"
                  className={styles.input}
                  placeholder="you@example.com"
                  value={form.email}
                  onChange={handleChange}
                  autoComplete="email"
                  aria-required="true"
                  aria-describedby={errors.email ? 'err-email' : undefined}
                />
              </div>
              {errors.email && (
                <span id="err-email" className={styles.fieldError} role="alert">
                  {errors.email}
                </span>
              )}
            </div>

            {/* Password */}
            <div className={styles.field}>
              <label htmlFor="reg-password" className={styles.label}>Password</label>
              <div className={`${styles.inputWrap} ${errors.password ? styles.hasError : ''}`}>
                <span className={styles.inputPrefix}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </span>
                <input
                  id="reg-password"
                  type={showPwd ? 'text' : 'password'}
                  name="password"
                  className={styles.input}
                  placeholder="Min. 6 characters"
                  value={form.password}
                  onChange={handleChange}
                  autoComplete="new-password"
                  aria-required="true"
                  aria-describedby={errors.password ? 'err-pwd' : 'pwd-strength'}
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
              {errors.password ? (
                <span id="err-pwd" className={styles.fieldError} role="alert">{errors.password}</span>
              ) : form.password ? (
                <div id="pwd-strength" className={styles.strengthRow}>
                  <div className={styles.strengthTrack}>
                    <div
                      className={styles.strengthFill}
                      style={{ width: strength.width, background: strength.color }}
                    />
                  </div>
                  <span className={styles.strengthLabel} style={{ color: strength.color }}>
                    {strength.label}
                  </span>
                </div>
              ) : null}
            </div>

            {/* Confirm Password */}
            <div className={styles.field}>
              <label htmlFor="reg-confirm" className={styles.label}>Confirm Password</label>
              <div className={`${styles.inputWrap} ${errors.confirmPassword ? styles.hasError : ''}`}>
                <span className={styles.inputPrefix}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </span>
                <input
                  id="reg-confirm"
                  type={showConfirm ? 'text' : 'password'}
                  name="confirmPassword"
                  className={styles.input}
                  placeholder="Repeat your password"
                  value={form.confirmPassword}
                  onChange={handleChange}
                  autoComplete="new-password"
                  aria-required="true"
                  aria-describedby={errors.confirmPassword ? 'err-confirm' : undefined}
                />
                <button
                  type="button"
                  className={styles.eye}
                  onClick={() => setShowConfirm((v) => !v)}
                  aria-label={showConfirm ? 'Hide' : 'Show'}
                >
                  {showConfirm
                    ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                    : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  }
                </button>
              </div>
              {errors.confirmPassword && (
                <span id="err-confirm" className={styles.fieldError} role="alert">
                  {errors.confirmPassword}
                </span>
              )}
            </div>

            {/* Submit */}
            <button
              id="register-submit"
              type="submit"
              className={styles.submitBtn}
              disabled={loading}
              aria-busy={loading}
            >
              {loading ? (
                <span className={styles.loadingRow}>
                  <span className={styles.spinner} aria-hidden="true" />
                  Creating Account…
                </span>
              ) : (
                <>
                  Create Account
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </>
              )}
            </button>
          </form>

          {/* Google Sign-Up */}
          <div className={styles.dividerRow}>
            <span className={styles.dividerLine} />
            <span className={styles.dividerText}>OR</span>
            <span className={styles.dividerLine} />
          </div>

          <GoogleSignInButton
            onError={(msg) => showError(msg)}
            buttonText="Continue with Google"
          />

          <p className={styles.loginPrompt}>
            Already have an account?{' '}
            <Link to="/login" className={styles.loginLink} id="go-to-login">
              Sign In
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}
