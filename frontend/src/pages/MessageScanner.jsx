import { useState, useEffect } from 'react';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './MessageScanner.module.css';

export default function MessageScanner() {
  const [userName, setUserName] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getMe()
      .then((data) => setUserName(data.full_name))
      .catch(() => null);
  }, []);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!message.trim()) {
      setError('Please paste or type a message to analyze.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await api.analyzeMessage({ message: message.trim() });
      setResult(data);
    } catch (err) {
      console.error('Message analysis error:', err);
      setError(err.message || 'Analysis failed. Please try again.');
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
          <h1 className={styles.pageTitle}>MESSAGE SCAM DETECTOR</h1>
          <p className={styles.pageSubtitle}>
            Check suspicious SMS, WhatsApp messages, emails, or urgent requests before you respond or share information.
          </p>
        </div>

        {error && <div className={styles.errorBanner}>⚠ {error}</div>}

        {/* ── SCANNER INPUT ── */}
        <section className={styles.scannerCard}>
          <form onSubmit={handleAnalyze} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label className={styles.textareaLabel}>Suspicious Message Content</label>
              <textarea
                className={styles.textarea}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Paste suspicious SMS, WhatsApp message, email text, or payment demand here…"
              />
            </div>

            <div className={styles.actionRow}>
              <button type="submit" className={styles.primaryBtn} disabled={loading}>
                {loading ? 'ANALYZING MESSAGE…' : 'ANALYZE MESSAGE'}
              </button>
              {message && (
                <button
                  type="button"
                  className={styles.clearBtn}
                  onClick={() => {
                    setMessage('');
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
                <span className={styles.scoreLabel}>COMBINED RISK SCORE</span>
                <span className={styles.scoreNumber}>{result.risk_score}/100</span>
              </div>
            </div>

            {/* ── AI / ML PREDICTION CARD ── */}
            {(result.prediction || result.ml_prediction) && (() => {
              const pred = result.prediction || result.ml_prediction;
              const rawConf = result.confidence ?? result.ml_confidence ?? 0;
              const confDisplay = rawConf > 1 ? rawConf.toFixed(1) : (rawConf * 100).toFixed(1);
              const rawScam = result.scam_probability ?? 0;
              const scamDisplay = rawScam > 1 ? rawScam.toFixed(1) : (rawScam * 100).toFixed(1);
              const rawSafe = result.safe_probability ?? 0;
              const safeDisplay = rawSafe > 1 ? rawSafe.toFixed(1) : (rawSafe * 100).toFixed(1);
              const scamWidth = rawScam > 1 ? rawScam : rawScam * 100;
              const safeWidth = rawSafe > 1 ? rawSafe : rawSafe * 100;

              return (
                <div className={styles.mlCard}>
                  <div className={styles.mlHeader}>
                    <span className={styles.mlTag}>
                      🤖 Machine Learning Analysis
                    </span>
                    <span className={styles.mlModelName}>
                      Model: {result.model || 'Logistic Regression'} (Baseline SMS Classifier)
                    </span>
                  </div>

                  <div className={styles.mlMetricsGrid}>
                    <div className={styles.mlMetricBox}>
                      <span className={styles.mlMetricLabel}>ML Verdict</span>
                      <span
                        className={styles.mlMetricValue}
                        style={{ color: pred === 'SCAM' ? '#dc2626' : '#16a34a' }}
                      >
                        {pred}
                      </span>
                    </div>
                    <div className={styles.mlMetricBox}>
                      <span className={styles.mlMetricLabel}>ML Confidence</span>
                      <span className={styles.mlMetricValue}>
                        {confDisplay}%
                      </span>
                    </div>
                    <div className={styles.mlMetricBox}>
                      <span className={styles.mlMetricLabel}>Scam Probability</span>
                      <span className={styles.mlMetricValue}>
                        {scamDisplay}%
                      </span>
                    </div>
                  </div>

                  <div className={styles.mlProbContainer}>
                    <div className={styles.mlProbHeader}>
                      <span>Safe Probability: {safeDisplay}%</span>
                      <span>Scam Probability: {scamDisplay}%</span>
                    </div>
                    <div className={styles.mlProbTrack}>
                      <div
                        className={styles.mlProbFillSafe}
                        style={{ width: `${safeWidth}%` }}
                      />
                      <div
                        className={styles.mlProbFillScam}
                        style={{ width: `${scamWidth}%` }}
                      />
                    </div>
                  </div>

                  <div className={styles.modelScopeNote}>
                    * Trained on the SMS Spam Collection benchmark dataset. Combined with heuristic pattern checks for layered cyber-defense.
                  </div>
                </div>
              );
            })()}

            <div>
              <span className={styles.scoreLabel}>DETECTION SUMMARY</span>
              <p className={styles.summaryText} style={{ marginTop: '6px' }}>
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
                <span className={styles.scoreLabel}>SECURITY REASONS & SIGNALS</span>
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
