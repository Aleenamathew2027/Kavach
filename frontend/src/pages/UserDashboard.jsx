import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './UserDashboard.module.css';

export default function UserDashboard() {
  const [userProfile, setUserProfile] = useState(null);
  const [securitySummary, setSecuritySummary] = useState(null);
  const [guardianCode, setGuardianCode] = useState(null);
  const [guardianExpiry, setGuardianExpiry] = useState(null);
  const [codeMsg, setCodeMsg] = useState('');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [profile, summary] = await Promise.all([
          api.getMe().catch(() => null),
          api.getSecuritySummary().catch(() => null),
        ]);
        if (profile) setUserProfile(profile);
        if (summary) setSecuritySummary(summary);
      } catch (err) {
        console.error('Error loading user dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleGenerateCode = async () => {
    try {
      setCodeMsg('Generating code…');
      const data = await api.generateGuardianCode();
      setGuardianCode(data.code);
      setGuardianExpiry(new Date(data.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
      setCodeMsg('Code active for 24 hours. Share this with your trusted guardian.');
    } catch (err) {
      console.error('Guardian generation error:', err);
      setCodeMsg(err.message || 'Unable to generate your guardian access code. Please try again.');
    }
  };

  const handleRevokeCode = async () => {
    try {
      await api.revokeGuardianCode();
      setGuardianCode(null);
      setGuardianExpiry(null);
      setCodeMsg('Guardian access code revoked.');
    } catch (err) {
      console.error('Guardian revoke error:', err);
      setCodeMsg(err.message || 'Unable to revoke code. Please try again.');
    }
  };

  const handleCopyCode = () => {
    if (!guardianCode) return;
    navigator.clipboard.writeText(guardianCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isAttentionRequired = securitySummary && (securitySummary.threats_detected > 0 || securitySummary.active_threat_level === 'HIGH');

  return (
    <div className={styles.page}>
      <UserNav userName={userProfile?.full_name || 'Kavach User'} />

      {/* ── MAIN CONTENT ── */}
      <main className={styles.main}>
        {/* ── HERO SECTION ── */}
        <section className={styles.heroGrid}>
          <div className={styles.heroLeft}>
            <h1 className={styles.heroHeading}>
              YOUR DIGITAL<br />
              SECURITY,<br />
              SIMPLIFIED.
            </h1>
            <p className={styles.heroSub}>
              Kavach continuously monitors your digital interactions and helps protect you from suspicious activity across messages, links, and documents.
            </p>
          </div>

          <div
            className={styles.statusCard}
            style={isAttentionRequired ? { background: '#451a03', borderColor: '#78350f' } : {}}
          >
            <div className={styles.statusLabel}>SECURITY STATUS</div>
            <div className={styles.statusMain}>
              <div className={styles.statusTitle}>
                <span
                  className={styles.statusDot}
                  style={isAttentionRequired ? { background: '#f59e0b' } : {}}
                />
                {isAttentionRequired ? 'ATTENTION REQUIRED' : 'PROTECTED'}
              </div>
              <div className={styles.statusDetail}>
                {isAttentionRequired
                  ? `${securitySummary.threats_detected} high-risk threat(s) detected in your scans.`
                  : 'No immediate threats detected across your scans.'}
              </div>
            </div>
            <div className={styles.statusFooter}>
              <span>Protection Engine Active</span>
              <span>Total Scans: {securitySummary?.total_scans ?? 0}</span>
            </div>
          </div>
        </section>

        {/* ── SECURITY METRICS ── */}
        <section className={styles.statsSection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>SECURITY METRICS</h2>
            <span style={{ fontSize: '12px', color: '#737373' }}>Real-time database telemetry</span>
          </div>

          <div className={styles.statsGrid}>
            <div className={styles.statBlock}>
              <span className={styles.statLabel}>THREATS DETECTED</span>
              <span className={styles.statNumber} style={isAttentionRequired ? { color: '#dc2626' } : {}}>
                {securitySummary?.threats_detected ?? 0}
              </span>
            </div>

            <div className={styles.statBlock}>
              <span className={styles.statLabel}>SUSPICIOUS MESSAGES</span>
              <span className={styles.statNumber}>
                {securitySummary?.suspicious_messages ?? 0}
              </span>
            </div>

            <div className={styles.statBlock}>
              <span className={styles.statLabel}>SUSPICIOUS LINKS</span>
              <span className={styles.statNumber}>
                {securitySummary?.suspicious_links ?? 0}
              </span>
            </div>

            <div className={styles.statBlock}>
              <span className={styles.statLabel}>SUSPICIOUS DOCUMENTS</span>
              <span className={styles.statNumber}>
                {securitySummary?.suspicious_documents ?? 0}
              </span>
            </div>
          </div>
        </section>

        {/* ── QUICK DETECTION MODULES LAUNCHPAD ── */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>DETECTION SCANNERS</h2>
            <span style={{ fontSize: '12px', color: '#737373' }}>Verify suspicious content before acting</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px' }}>
            <Link
              to="/user/messages"
              style={{
                background: '#ffffff',
                border: '1px solid #ebe7df',
                padding: '28px',
                textDecoration: 'none',
                color: 'inherit',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '16px',
                transition: 'border-color 0.2s',
              }}
            >
              <div>
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#1a3325', letterSpacing: '1px' }}>COMMUNICATION</span>
                <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '18px', fontWeight: 800, marginTop: '6px', color: '#1a3325' }}>
                  Message Scam Detector
                </h3>
                <p style={{ fontSize: '13.5px', color: '#4a5d4e', marginTop: '8px', lineHeight: 1.5 }}>
                  Paste suspicious SMS, WhatsApp messages, or emails to detect urgency and OTP demands.
                </p>
              </div>
              <span style={{ fontSize: '12px', fontWeight: 700, color: '#1a3325', textTransform: 'uppercase' }}>
                Open Detector →
              </span>
            </Link>

            <Link
              to="/user/link-checker"
              style={{
                background: '#ffffff',
                border: '1px solid #ebe7df',
                padding: '28px',
                textDecoration: 'none',
                color: 'inherit',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '16px',
                transition: 'border-color 0.2s',
              }}
            >
              <div>
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#1a3325', letterSpacing: '1px' }}>WEB SAFETY</span>
                <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '18px', fontWeight: 800, marginTop: '6px', color: '#1a3325' }}>
                  Link Safety Checker
                </h3>
                <p style={{ fontSize: '13.5px', color: '#4a5d4e', marginTop: '8px', lineHeight: 1.5 }}>
                  Inspect suspicious URLs, shortened links, and banking portals before visiting.
                </p>
              </div>
              <span style={{ fontSize: '12px', fontWeight: 700, color: '#1a3325', textTransform: 'uppercase' }}>
                Open Link Checker →
              </span>
            </Link>

            <Link
              to="/user/document-checker"
              style={{
                background: '#ffffff',
                border: '1px solid #ebe7df',
                padding: '28px',
                textDecoration: 'none',
                color: 'inherit',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '16px',
                transition: 'border-color 0.2s',
              }}
            >
              <div>
                <span style={{ fontSize: '11px', fontWeight: 700, color: '#1a3325', letterSpacing: '1px' }}>FILE SECURITY</span>
                <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '18px', fontWeight: 800, marginTop: '6px', color: '#1a3325' }}>
                  Document Scanner
                </h3>
                <p style={{ fontSize: '13.5px', color: '#4a5d4e', marginTop: '8px', lineHeight: 1.5 }}>
                  Upload suspicious PDF, DOCX, or TXT attachments to check for scam wording.
                </p>
              </div>
              <span style={{ fontSize: '12px', fontWeight: 700, color: '#1a3325', textTransform: 'uppercase' }}>
                Open Document Scanner →
              </span>
            </Link>
          </div>
        </section>

        {/* ── DUAL CONTENT: RECENT ACTIVITY & GUARDIAN ACCESS ── */}
        <div className={styles.contentRow}>
          {/* Recent Security Activity */}
          <section className={styles.activityCard}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>RECENT ACTIVITY</h2>
              <Link to="/user/alerts" style={{ fontSize: '12px', fontWeight: 700, color: '#1a3325', textDecoration: 'none' }}>
                VIEW ALL ALERTS →
              </Link>
            </div>

            <div className={styles.activityList}>
              <div className={styles.activityItem}>
                <div className={styles.activityInfo}>
                  <span className={styles.activityText}>Security Scanner Engine Active</span>
                  <span className={styles.activityTime}>Real-time protection</span>
                </div>
                <span className={styles.statusPill}>ACTIVE</span>
              </div>

              <div className={styles.activityItem}>
                <div className={styles.activityInfo}>
                  <span className={styles.activityText}>Deepfake Voice Firewall Active</span>
                  <span className={styles.activityTime}>Continuous monitoring</span>
                </div>
                <span className={styles.statusPill}>MONITORED</span>
              </div>

              <div className={styles.activityItem}>
                <div className={styles.activityInfo}>
                  <span className={styles.activityText}>PostgreSQL Security Log Synced</span>
                  <span className={styles.activityTime}>Encrypted Database</span>
                </div>
                <span className={styles.statusPill}>SECURE</span>
              </div>
            </div>
          </section>

          {/* Trusted Guardian Access */}
          <section className={styles.guardianCard}>
            <div>
              <div className={styles.sectionHeader} style={{ marginBottom: '16px' }}>
                <h2 className={styles.sectionTitle}>TRUSTED GUARDIAN ACCESS</h2>
              </div>
              <p className={styles.guardianDesc}>
                Share temporary access with someone you trust. Your guardian can monitor safety status without seeing your private messages or passwords.
              </p>
            </div>

            {guardianCode ? (
              <div>
                <div className={styles.codeBox}>
                  <div>
                    <span style={{ fontSize: '10.5px', color: '#737373', fontWeight: 700, letterSpacing: '1px' }}>
                      YOUR ACCESS CODE
                    </span>
                    <div className={styles.codeDigits}>{guardianCode}</div>
                  </div>
                  <button className={styles.outlineBtn} onClick={handleCopyCode}>
                    {copied ? 'COPIED' : 'COPY CODE'}
                  </button>
                </div>
                <div className={styles.codeNotice}>
                  Expires in: <strong>24 hours (until {guardianExpiry})</strong>
                </div>
                <div style={{ fontSize: '12px', color: '#b91c1c', marginTop: '6px' }}>
                  ⚠ Only share this code with someone you trust.
                </div>
                <div className={styles.buttonGroup}>
                  <button className={styles.dangerBtn} onClick={handleRevokeCode}>
                    REVOKE CODE
                  </button>
                </div>
              </div>
            ) : (
              <div>
                {codeMsg && (
                  <p style={{ fontSize: '13px', color: '#15803d', marginBottom: '14px' }}>
                    {codeMsg}
                  </p>
                )}
                <button className={styles.primaryBtn} onClick={handleGenerateCode}>
                  GENERATE ACCESS CODE
                </button>
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}
