import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, setAuth } from '../services/api';
import styles from './GoogleSignInButton.module.css';

export default function GoogleSignInButton({ onError, buttonText = 'Continue with Google' }) {
  const navigate = useNavigate();
  const googleBtnRef = useRef(null);
  const [loading, setLoading] = useState(false);
  const [sdkLoaded, setSdkLoaded] = useState(false);

  // Read Google Client ID from environment
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

  const handleGoogleCredentialResponse = async (response) => {
    if (!response || !response.credential) {
      if (onError) onError('Google authentication was cancelled or did not return a valid credential.');
      return;
    }

    setLoading(true);
    if (onError) onError('');

    try {
      const data = await api.googleLogin({ credential: response.credential });
      
      // Store JWT token and role authoritative from backend
      setAuth({ token: data.access_token, role: data.role || 'user' });

      // Redirect according to authoritative backend role
      if (data.role === 'admin') {
        navigate('/admin/dashboard', { replace: true });
      } else if (data.role === 'guardian') {
        navigate('/guardian/dashboard', { replace: true });
      } else {
        navigate('/user/dashboard', { replace: true });
      }
    } catch (err) {
      console.error('Google Sign-In backend error:', err);
      if (onError) {
        onError(err.message || 'Failed to authenticate with Google. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // 1. Check if Google Identity Services script already exists
    const existingScript = document.getElementById('google-gsi-client');

    const initializeGsi = () => {
      if (window.google?.accounts?.id && clientId) {
        try {
          window.google.accounts.id.initialize({
            client_id: clientId,
            callback: handleGoogleCredentialResponse,
            auto_select: false,
            cancel_on_tap_outside: true,
          });

          if (googleBtnRef.current) {
            googleBtnRef.current.innerHTML = '';
            window.google.accounts.id.renderButton(googleBtnRef.current, {
              theme: 'outline',
              size: 'large',
              type: 'standard',
              shape: 'rectangular',
              text: 'continue_with',
              logo_alignment: 'left',
              width: '100%',
            });
          }
          setSdkLoaded(true);
        } catch (e) {
          console.warn('Google GSI initialization notice:', e);
        }
      }
    };

    if (!existingScript) {
      const script = document.createElement('script');
      script.id = 'google-gsi-client';
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      script.onload = initializeGsi;
      document.body.appendChild(script);
    } else {
      if (window.google?.accounts?.id) {
        initializeGsi();
      } else {
        existingScript.addEventListener('load', initializeGsi);
      }
    }
  }, [clientId]);

  const handleManualClick = () => {
    if (loading) return;

    // If Google Client ID is configured and SDK is initialized, prompt account picker
    if (window.google?.accounts?.id && clientId) {
      window.google.accounts.id.prompt();
    } else {
      // If client ID is not yet provided in .env, inform user gracefully
      if (onError) {
        onError(
          'Google Client ID is not configured yet. Please add VITE_GOOGLE_CLIENT_ID to frontend/.env (and GOOGLE_CLIENT_ID to backend/.env).'
        );
      }
    }
  };

  return (
    <div className={styles.container}>
      {/* If Google renders its native iframe button */}
      <div
        ref={googleBtnRef}
        className={styles.nativeGoogleBtnWrap}
        style={{ display: sdkLoaded && clientId ? 'block' : 'none' }}
      />

      {/* Styled fallback button when SDK is loading or user clicks directly */}
      {(!sdkLoaded || !clientId) && (
        <button
          type="button"
          className={styles.googleBtn}
          onClick={handleManualClick}
          disabled={loading}
        >
          {loading ? (
            <span className={styles.spinner} />
          ) : (
            <svg className={styles.googleIcon} viewBox="0 0 24 24" width="18" height="18">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
          )}
          <span className={styles.btnText}>{loading ? 'Connecting to Google…' : buttonText}</span>
        </button>
      )}
    </div>
  );
}
