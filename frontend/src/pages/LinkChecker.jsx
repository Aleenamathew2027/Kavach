import { useState, useEffect } from 'react';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './LinkChecker.module.css';

export default function LinkChecker() {
  const [userName, setUserName] = useState('');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getMe()
      .then((data) => setUserName(data.full_name))
      .catch(() => null);
  }, []);

  const handleCheck = async (e) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL or web address to check.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await api.analyzeLink({ url: url.trim() });
      setResult(data);
    } catch (err) {
      console.error('Link check error:', err);
      setError(err.message || 'Link verification failed. Please check the URL syntax.');
    } finally {
      setLoading(false);
    }
  };

  const getBadgeClass = (riskLevel) => {
    if (riskLevel === 'HIGH RISK') return styles.badgeHigh;
    if (riskLevel === 'SUSPICIOUS') return styles.badgeSuspicious;
    return styles.badgeSafe;
  };

  return (
    <div className={styles.page}>
      <UserNav userName={userName} />

      <main className={styles.main}>
        <div className={styles.headerSection}>
          <h1 className={styles.pageTitle}>LINK SAFETY CHECKER</h1>
          <p className={styles.pageSubtitle}>
            Safely analyze suspicious URLs, shortened links, and banking portals before opening them in your browser.
          </p>
        </div>

        {error && <div className={styles.errorBanner}>⚠ {error}</div>}

        {/* ── SCANNER INPUT ── */}
        <section className={styles.scannerCard}>
          <form onSubmit={handleCheck} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label className={styles.inputLabel}>URL / Link Address</label>
              <input
                type="text"
                className={styles.urlInput}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. https://secure-login-bank.xyz/verify or bit.ly/claim-prize"
              />
            </div>

            <div className={styles.actionRow}>
              <button type="submit" className={styles.primaryBtn} disabled={loading}>
                {loading ? 'CHECKING LINK SAFETY…' : 'CHECK LINK'}
              </button>
              {url && (
                <button
                  type="button"
                  className={styles.clearBtn}
                  onClick={() => {
                    setUrl('');
                    setResult(null);
                    setError('');
                  }}
                >
                  CLEAR
                </button>
              )}
            </div>
          </form>
        </section>

        {/* ── SCAN RESULT ── */}
        {result && (
          <section className={styles.resultSection}>
            <div className={styles.resultHeader}>
              <div>
                <span className={`${styles.riskBadge} ${getBadgeClass(result.risk_level)}`}>
                  {result.risk_level}
                </span>
              </div>
              <div className={styles.scoreGroup}>
                <span className={styles.scoreLabel}>RISK SCORE</span>
                <span className={styles.scoreNumber}>{result.risk_score}/100</span>
              </div>
            </div>

            <div>
              <span className={styles.scoreLabel}>ANALYZED URL</span>
              <div className={styles.urlDisplay}>{result.url}</div>
            </div>

            <div>
              <span className={styles.scoreLabel}>DETECTION RESULT</span>
              <p style={{ fontSize: '15.5px', fontWeight: 600, color: '#1a1a1a', marginTop: '6px' }}>
                {result.summary}
              </p>
            </div>

            {result.detected_indicators && result.detected_indicators.length > 0 && (
              <div>
                <span className={styles.scoreLabel}>DETECTED INDICATORS</span>
                <div className={styles.indicatorsList}>
                  {result.detected_indicators.map((ind) => (
                    <span key={ind} className={styles.indicatorPill}>
                      • {ind}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.reasons && result.reasons.length > 0 && (
              <div>
                <span className={styles.scoreLabel}>SECURITY REASONS</span>
                <ul className={styles.reasonsList} style={{ marginTop: '8px' }}>
                  {result.reasons.map((r, i) => (
                    <li key={i} className={styles.reasonItem}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className={styles.actionBox}>
              <span className={styles.actionBoxTitle}>RECOMMENDED ACTION</span>
              <span className={styles.actionBoxText}>{result.recommended_action}</span>
            </div>

            {result.alert_created && (
              <div style={{ fontSize: '12px', color: '#991b1b', fontWeight: 600 }}>
                🚨 High-risk incident logged to your Security Alerts and family guardian feed.
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
