import { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './DocumentChecker.module.css';

export default function DocumentChecker() {
  const [userName, setUserName] = useState('');
  const [file, setFile] = useState(null);
  const [statusText, setStatusText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  useEffect(() => {
    api.getMe()
      .then((data) => setUserName(data.full_name))
      .catch(() => null);
  }, []);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      if (selected.size > 10 * 1024 * 1024) {
        setError('File is too large. Maximum size is 10MB.');
        return;
      }
      setFile(selected);
      setError('');
      setResult(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const dropped = e.dataTransfer.files[0];
      if (dropped.size > 10 * 1024 * 1024) {
        setError('File is too large. Maximum size is 10MB.');
        return;
      }
      setFile(dropped);
      setError('');
      setResult(null);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select or drop a document to scan.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setStatusText('Uploading document…');

    try {
      setTimeout(() => {
        if (loading) setStatusText('Extracting and analyzing text content safely…');
      }, 500);

      const formData = new FormData();
      formData.append('file', file);

      const data = await api.analyzeDocument(formData);
      setResult(data);
      setStatusText('Scan complete.');
    } catch (err) {
      console.error('Document scan error:', err);
      setError(err.message || 'Failed to analyze document.');
      setStatusText('');
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
          <h1 className={styles.pageTitle}>DOCUMENT SECURITY SCANNER</h1>
          <p className={styles.pageSubtitle}>
            Upload a suspicious document (PDF, Word, or Text) to check for fraudulent payment demands, legal threats, and scam indicators.
          </p>
        </div>

        {error && <div className={styles.errorBanner}>⚠ {error}</div>}

        {/* ── UPLOAD AREA ── */}
        <section className={styles.uploadCard}>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pdf,.docx,.doc,.txt,.png,.jpg,.jpeg"
            style={{ display: 'none' }}
          />

          {!file ? (
            <div
              className={styles.dropZone}
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
            >
              <div className={styles.dropIcon}>📄</div>
              <div className={styles.dropText}>Drag &amp; drop your document here, or click to browse</div>
              <div className={styles.dropSub}>Supported formats: PDF, DOCX, TXT, PNG, JPG (Max 10MB)</div>
            </div>
          ) : (
            <div className={styles.fileSelectedBadge}>
              <div>
                <div className={styles.fileName}>{file.name}</div>
                <div className={styles.fileSize}>{(file.size / 1024).toFixed(1)} KB</div>
              </div>
              <button
                type="button"
                className={styles.clearBtn}
                style={{ padding: '6px 14px', fontSize: '11px' }}
                onClick={() => {
                  setFile(null);
                  setResult(null);
                  setStatusText('');
                }}
              >
                REMOVE
              </button>
            </div>
          )}

          <div className={styles.actionRow}>
            <button
              type="button"
              className={styles.primaryBtn}
              onClick={handleScan}
              disabled={!file || loading}
            >
              {loading ? 'SCANNING DOCUMENT…' : 'SCAN DOCUMENT'}
            </button>

            {statusText && <span className={styles.statusMessage}>{statusText}</span>}
          </div>
        </section>

        {/* ── SCAN RESULT ── */}
        {result && (
          <section className={styles.resultSection}>
            <div className={styles.resultHeader}>
              <div>
                <span className={`${styles.riskBadge} ${getBadgeClass(result.risk_level)}`}>
                  {result.risk_level}
                </span>
                <div style={{ fontSize: '12px', color: '#737373', marginTop: '6px', fontWeight: 600 }}>
                  {result.filename} • {result.file_type}
                </div>
              </div>
              <div className={styles.scoreGroup}>
                <span className={styles.scoreLabel}>RISK SCORE</span>
                <span className={styles.scoreNumber}>{result.risk_score}/100</span>
              </div>
            </div>

            <div>
              <span className={styles.scoreLabel}>DETECTION RESULT</span>
              <p style={{ fontSize: '15.5px', fontWeight: 600, color: '#1a1a1a', marginTop: '6px' }}>
                {result.summary}
              </p>
            </div>

            {result.text_preview && (
              <div>
                <span className={styles.scoreLabel}>SAFE EXTRACTED TEXT PREVIEW</span>
                <div className={styles.previewBox}>{result.text_preview}</div>
              </div>
            )}

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
                🚨 High-risk document threat logged to your Security Alerts and guardian feed.
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
