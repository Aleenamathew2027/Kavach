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
        if (loading) setStatusText('Running OCR & text extraction engine…');
      }, 400);

      setTimeout(() => {
        if (loading) setStatusText('Scanning extracted links & decoding embedded QR codes…');
      }, 1000);

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
    if (!riskLevel) return styles.badgeUnknown;
    const lvl = riskLevel.toString().toUpperCase();
    if (lvl === 'HIGH RISK' || lvl === 'HIGH_RISK') return styles.badgeHigh;
    if (lvl === 'SUSPICIOUS') return styles.badgeSuspicious;
    if (lvl === 'UNKNOWN' || lvl === 'OCR_UNAVAILABLE' || lvl === 'FAILED') return styles.badgeUnknown;
    return styles.badgeSafe;
  };

  return (
    <div className={styles.page}>
      <UserNav userName={userName} />

      <main className={styles.main}>
        <div className={styles.headerSection}>
          <h1 className={styles.pageTitle}>DOCUMENT &amp; IMAGE SCAM SCANNER</h1>
          <p className={styles.pageSubtitle}>
            Multi-engine security scanner combining OCR text extraction, ML message scam detection, hybrid URL link inspection, and embedded QR code analysis.
          </p>
        </div>

        {error && <div className={styles.errorBanner}>⚠ {error}</div>}

        {/* ── UPLOAD AREA ── */}
        <section className={styles.uploadCard}>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pdf,.docx,.doc,.txt,.png,.jpg,.jpeg,.bmp,.webp"
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
              <div className={styles.dropText}>Drag &amp; drop your document or image here, or click to browse</div>
              <div className={styles.dropSub}>Supported formats: PDF, DOCX, TXT, PNG, JPG, JPEG, WEBP, BMP (Max 10MB)</div>
            </div>
          ) : (
            <div className={styles.fileSelectedBadge}>
              <div>
                <div className={styles.fileName}>{file.name}</div>
                <div className={styles.fileSize}>{(file.size / 1024).toFixed(1)} KB • {file.type || 'Document'}</div>
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
              {loading ? 'SCANNING MULTI-ENGINE…' : 'SCAN DOCUMENT'}
            </button>

            {statusText && <span className={styles.statusMessage}>{statusText}</span>}
          </div>
        </section>

        {/* ── SCAN RESULT ── */}
        {result && (
          <section className={styles.resultSection}>
            {/* Overall Header */}
            <div className={styles.resultHeader}>
              <div>
                <span className={`${styles.riskBadge} ${getBadgeClass(result.risk_level)}`}>
                  {result.risk_level}
                </span>
                <div style={{ fontSize: '12.5px', color: '#737373', marginTop: '8px', fontWeight: 600 }}>
                  {result.filename} • {result.file_type} {result.scan_id ? `• Scan ID: #${result.scan_id}` : ''}
                </div>
              </div>
              <div className={styles.scoreGroup}>
                <span className={styles.scoreLabel}>OVERALL RISK SCORE</span>
                <span className={styles.scoreNumber}>{result.risk_score}/100</span>
              </div>
            </div>

            {/* Sub-Engine Breakdown Cards */}
            {result.threat_breakdown && (
              <div className={styles.engineGrid}>
                <div className={styles.engineCard}>
                  <div className={styles.engineLabel}>TEXT ML RISK</div>
                  <div className={styles.engineScore}>{result.threat_breakdown.text_risk_score}/100</div>
                  <div className={styles.engineSub}>{result.text_analysis?.verdict || 'SAFE'}</div>
                </div>

                <div className={styles.engineCard}>
                  <div className={styles.engineLabel}>URL SCAM RISK</div>
                  <div className={styles.engineScore}>{result.threat_breakdown.url_risk_score}/100</div>
                  <div className={styles.engineSub}>{result.url_analysis?.url_count || 0} Link(s) Analyzed</div>
                </div>

                <div className={styles.engineCard}>
                  <div className={styles.engineLabel}>QR CODE RISK</div>
                  <div className={styles.engineScore}>{result.threat_breakdown.qr_risk_score}/100</div>
                  <div className={styles.engineSub}>{result.qr_analysis?.qr_count || 0} QR(s) Detected</div>
                </div>
              </div>
            )}

            <div>
              <span className={styles.scoreLabel}>SUMMARY VERDICT</span>
              <p style={{ fontSize: '15.5px', fontWeight: 600, color: '#1a1a1a', marginTop: '6px' }}>
                {result.summary}
              </p>
            </div>

            {/* OCR Info Metadata */}
            {result.ocr_info && (
              <div className={styles.ocrInfoBox}>
                <span className={styles.scoreLabel}>OCR &amp; DOCUMENT METADATA</span>
                <div className={styles.ocrMetaRow}>
                  <span>Status: <strong>{result.ocr_info.status}</strong></span>
                  <span>Pages: <strong>{result.ocr_info.page_count}</strong></span>
                  <span>Words: <strong>{result.ocr_info.word_count}</strong></span>
                  <span>Characters: <strong>{result.ocr_info.character_count}</strong></span>
                </div>
                {result.ocr_info.status === 'OCR_UNAVAILABLE' && (
                  <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '6px', fontWeight: 500 }}>
                    ℹ OCR engine binary (Tesseract) is unavailable on host OS. Native PDF/DOCX text extraction and QR code scanner executed cleanly.
                  </div>
                )}
              </div>
            )}

            {/* Text Preview */}
            {result.text_preview && (
              <div>
                <span className={styles.scoreLabel}>SAFE EXTRACTED TEXT PREVIEW</span>
                <div className={styles.previewBox}>{result.text_preview}</div>
              </div>
            )}

            {/* Extracted URLs Table / Cards */}
            {result.url_analysis && result.url_analysis.analyzed_urls && result.url_analysis.analyzed_urls.length > 0 && (
              <div>
                <span className={styles.scoreLabel}>EXTRACTED LINKS ANALYSIS ({result.url_analysis.url_count})</span>
                <div className={styles.urlList}>
                  {result.url_analysis.analyzed_urls.map((uItem, idx) => (
                    <div key={idx} className={styles.urlCard}>
                      <div className={styles.urlCardHeader}>
                        <span className={styles.urlText}>{uItem.url}</span>
                        <span className={`${styles.riskBadgeSmall} ${getBadgeClass(uItem.verdict || uItem.risk_level)}`}>
                          {uItem.verdict || uItem.risk_level} ({uItem.risk_score}/100)
                        </span>
                      </div>
                      {uItem.reasons && uItem.reasons.length > 0 && (
                        <div className={styles.urlReasons}>
                          {uItem.reasons.map((r, ri) => <div key={ri}>• {r}</div>)}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* QR Codes Section */}
            {result.qr_analysis && result.qr_analysis.qr_found && (
              <div>
                <span className={styles.scoreLabel}>EMBEDDED QR CODES DETECTED ({result.qr_analysis.qr_count})</span>
                <div className={styles.qrList}>
                  {result.qr_analysis.qr_codes.map((qr, qidx) => (
                    <div key={qidx} className={styles.qrCard}>
                      <div className={styles.qrCardHeader}>
                        <span className={styles.qrTypeBadge}>
                          QR Payload Type: <strong>{qr.payload_type}</strong> {qr.page_number ? `(Page ${qr.page_number})` : ''}
                        </span>
                        <span className={`${styles.riskBadgeSmall} ${getBadgeClass(qr.risk_score >= 70 ? 'HIGH RISK' : qr.risk_score >= 40 ? 'SUSPICIOUS' : 'SAFE')}`}>
                          Risk Score: {qr.risk_score}/100
                        </span>
                      </div>
                      <div className={styles.qrPayloadPreview}>
                        Payload: <code>{qr.payload}</code>
                      </div>
                      {qr.reasons && qr.reasons.length > 0 && (
                        <div className={styles.urlReasons}>
                          {qr.reasons.map((r, ri) => <div key={ri}>• {r}</div>)}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detected Indicators */}
            {result.detected_indicators && result.detected_indicators.length > 0 && (
              <div>
                <span className={styles.scoreLabel}>CONSOLIDATED THREAT INDICATORS</span>
                <div className={styles.indicatorsList}>
                  {result.detected_indicators.map((ind) => (
                    <span key={ind} className={styles.indicatorPill}>
                      • {ind}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Reasons List */}
            {result.reasons && result.reasons.length > 0 && (
              <div>
                <span className={styles.scoreLabel}>SECURITY REASONS &amp; EXPLANATIONS</span>
                <ul className={styles.reasonsList} style={{ marginTop: '8px' }}>
                  {result.reasons.map((r, i) => (
                    <li key={i} className={styles.reasonItem}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Unscannable Warning Banner */}
            {(result.risk_level === 'UNSCANNABLE' || result.risk_level === 'UNKNOWN') && (
              <div className={styles.unscannableWarningBox}>
                ⚠ This file could not be fully analyzed. Do not trust it without verifying the source.
              </div>
            )}

            {/* Recommended Guidance Box */}
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
