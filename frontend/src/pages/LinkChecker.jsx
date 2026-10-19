import { useState } from 'react';
import { api } from '../services/api';
import UserLayout from '../components/UserLayout';
import styles from './LinkChecker.module.css';

export default function LinkChecker() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const handleCheck = async (targetUrl = null) => {
    const inputUrl = typeof targetUrl === 'string' ? targetUrl : url;
    if (!inputUrl || !inputUrl.trim()) {
      setError('Please enter a URL or web address to analyze.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await api.analyzeLink({ url: inputUrl.trim() });
      setResult(data);
    } catch (err) {
      console.error('Link check error:', err);
      setError(err.message || 'Link verification failed. Please check the URL syntax.');
    } finally {
      setLoading(false);
    }
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    handleCheck();
  };

  const handleSampleClick = (sampleUrl) => {
    setUrl(sampleUrl);
    handleCheck(sampleUrl);
  };

  const handleCopyUrl = () => {
    if (result?.url) {
      navigator.clipboard.writeText(result.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getVerdictClass = (verdict) => {
    if (verdict === 'HIGH RISK') return styles.verdictHigh;
    if (verdict === 'SUSPICIOUS') return styles.verdictSuspicious;
    return styles.verdictSafe;
  };

  const getBadgeClass = (verdict) => {
    if (verdict === 'HIGH RISK') return styles.badgeHigh;
    if (verdict === 'SUSPICIOUS') return styles.badgeSuspicious;
    return styles.badgeSafe;
  };

  return (
    <UserLayout
      eyebrow="ZERO-DAY SENTRY"
      title="LINK SECURITY CHECKER"
      subtitle="Analyze suspicious URLs before opening them. Multi-layered inspection combining 20+ static heuristics and trained ML."
    >
      <div className={styles.scannerWrapper}>
        {error && <div className={styles.errorBanner}>⚠ {error}</div>}

        {/* ── SCANNER INPUT ── */}
        <section className={styles.scannerCard}>
          <form onSubmit={handleFormSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label className={styles.inputLabel}>PASTE SUSPICIOUS URL / WEB ADDRESS</label>
              <input
                type="text"
                className={styles.urlInput}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. https://secure-login-example.com@evil.example/verify or bit.ly/claim-prize"
              />
            </div>

            {/* Quick Test Samples */}
            <div className={styles.sampleSection}>
              <span className={styles.sampleLabel}>TEST SYNTHETIC SAMPLES:</span>
              <div className={styles.sampleChips}>
                <button
                  type="button"
                  className={styles.sampleChipSafe}
                  onClick={() => handleSampleClick('https://www.google.com')}
                >
                  ✓ Google (Safe)
                </button>
                <button
                  type="button"
                  className={styles.sampleChipSafe}
                  onClick={() => handleSampleClick('https://www.wikipedia.org')}
                >
                  ✓ Wikipedia (Safe)
                </button>
                <button
                  type="button"
                  className={styles.sampleChipSuspicious}
                  onClick={() => handleSampleClick('http://example-login.com/verify')}
                >
                  ⚠ Suspicious Login
                </button>
                <button
                  type="button"
                  className={styles.sampleChipHighRisk}
                  onClick={() => handleSampleClick('https://secure-login-example.com@evil.example/verify')}
                >
                  🚨 High-Risk Phishing
                </button>
              </div>
            </div>

            <div className={styles.actionRow}>
              <button type="submit" className={styles.primaryBtn} disabled={loading}>
                {loading ? 'ANALYZING LINK SAFETY…' : 'CHECK LINK'}
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

        {/* ── SCAN RESULT CARD ── */}
        {result && (
          <section className={`${styles.resultCard} ${getVerdictClass(result.verdict || result.risk_level)}`}>
            <div className={styles.resultHeader}>
              <div className={styles.verdictGroup}>
                <span className={`${styles.riskBadge} ${getBadgeClass(result.verdict || result.risk_level)}`}>
                  {result.verdict || result.risk_level}
                </span>
                <span className={styles.analysisTypeBadge}>
                  {result.analysis_type || 'Hybrid URL Security Engine (Heuristic + ML)'} • Confidence {result.confidence || 90}%
                </span>
              </div>
              <div className={styles.scoreGroup}>
                <span className={styles.scoreLabel}>OVERALL RISK SCORE</span>
                <span className={styles.scoreNumber}>{result.risk_score} <span className={styles.scoreMax}>/ 100</span></span>
              </div>
            </div>

            <div className={styles.urlBlock}>
              <div className={styles.urlHeaderRow}>
                <span className={styles.sectionLabel}>ANALYZED URL</span>
                <button type="button" className={styles.copyBtn} onClick={handleCopyUrl}>
                  {copied ? '✓ COPIED' : 'COPY URL'}
                </button>
              </div>
              <div className={styles.urlDisplay}>{result.url}</div>
            </div>

            {/* ── LAYERED DETECTION BREAKDOWN (HEURISTICS + ML) ── */}
            <div className={styles.engineBreakdownGrid}>
              {/* HEURISTIC ANALYSIS CARD */}
              <div className={styles.breakdownCard}>
                <div className={styles.breakdownHeader}>
                  <span className={styles.breakdownTitle}>1. HEURISTIC ANALYSIS</span>
                  <span className={styles.breakdownScore}>
                    Score: {result.heuristic_score ?? result.risk_score}/100
                  </span>
                </div>
                <p className={styles.breakdownSub}>Evaluates 20+ static URL structural & domain reputation signals.</p>
                {((result.indicators && result.indicators.length > 0) || (result.detected_indicators && result.detected_indicators.length > 0)) ? (
                  <div className={styles.indicatorsList}>
                    {(result.indicators || result.detected_indicators).map((ind, i) => (
                      <span key={i} className={styles.indicatorPill}>
                        ⚠ {ind}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className={styles.safeSubtext}>✓ No suspicious heuristic anomalies detected.</div>
                )}
              </div>

              {/* MACHINE LEARNING CLASSIFICATION CARD */}
              <div className={styles.breakdownCard}>
                <div className={styles.breakdownHeader}>
                  <span className={styles.breakdownTitle}>2. MACHINE LEARNING MODEL</span>
                  <span className={styles.mlBadge}>{result.model || 'Random Forest Classifier'}</span>
                </div>
                <p className={styles.breakdownSub}>Scope: {result.model_scope || 'ISCX Phishing Benchmark'}</p>
                
                <div className={styles.mlStatRow}>
                  <div className={styles.mlStatBox}>
                    <span className={styles.mlStatLabel}>ML VERDICT</span>
                    <span className={result.ml_verdict === 'PHISHING' ? styles.mlPhishText : styles.mlSafeText}>
                      {result.ml_verdict || (result.risk_score >= 50 ? 'PHISHING' : 'SAFE')}
                    </span>
                  </div>
                  <div className={styles.mlStatBox}>
                    <span className={styles.mlStatLabel}>PHISHING PROBABILITY</span>
                    <span className={styles.mlStatVal}>{result.ml_phishing_probability ?? (result.risk_score)}%</span>
                  </div>
                  <div className={styles.mlStatBox}>
                    <span className={styles.mlStatLabel}>SAFE PROBABILITY</span>
                    <span className={styles.mlStatVal}>{result.ml_safe_probability ?? (100 - result.risk_score)}%</span>
                  </div>
                </div>
              </div>
            </div>

            <div className={styles.verdictSummaryBox}>
              <span className={styles.sectionLabel}>WHY KAVACH FLAGGED THIS</span>
              <p className={styles.summaryText}>{result.summary}</p>
            </div>

            {result.reasons && result.reasons.length > 0 && (
              <div className={styles.reasonsBlock}>
                <span className={styles.sectionLabel}>DETAILED SECURITY ANALYSIS</span>
                <ul className={styles.reasonsList}>
                  {result.reasons.map((r, i) => (
                    <li key={i} className={styles.reasonItem}>
                      <span className={styles.bulletIcon}>•</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className={styles.actionBox}>
              <span className={styles.actionBoxTitle}>FINAL KAVACH RECOMMENDATION</span>
              <span className={styles.actionBoxText}>
                {result.recommendation || result.recommended_action}
              </span>
            </div>

            {result.alert_created && (
              <div className={styles.alertNoticeBanner}>
                🚨 <strong>HIGH-RISK INCIDENT RECORDED:</strong> An alert has been automatically logged to your Security Alerts dashboard and made accessible to your family guardian feed.
              </div>
            )}
          </section>
        )}
      </div>
    </UserLayout>
  );
}
