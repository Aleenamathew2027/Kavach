import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import UserLayout from '../components/UserLayout';
import styles from './UserDashboard.module.css';

export default function UserGuardian() {
  const [guardianCode, setGuardianCode] = useState(null);
  const [guardianExpiry, setGuardianExpiry] = useState(null);
  const [codeMsg, setCodeMsg] = useState('');
  const [codeError, setCodeError] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerateCode = async () => {
    try {
      setCodeMsg('Generating cryptographic code…');
      setCodeError(false);
      const data = await api.generateGuardianCode();
      setGuardianCode(data.code);
      setGuardianExpiry(
        new Date(data.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      );
      setCodeMsg('Access code active for 24 hours. Share this with your trusted guardian.');
    } catch (err) {
      console.error('Guardian generation error:', err);
      setCodeError(true);
      setCodeMsg(err.message || 'Unable to generate guardian access code. Please try again.');
    }
  };

  const handleRevokeCode = async () => {
    try {
      setCodeError(false);
      await api.revokeGuardianCode();
      setGuardianCode(null);
      setGuardianExpiry(null);
      setCodeMsg('Guardian access code revoked.');
    } catch (err) {
      console.error('Guardian revoke error:', err);
      setCodeError(true);
      setCodeMsg(err.message || 'Unable to revoke code. Please try again.');
    }
  };

  const handleCopyCode = () => {
    if (!guardianCode) return;
    navigator.clipboard.writeText(guardianCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <UserLayout
      eyebrow="FAMILY PROTECTION NETWORK"
      title="TRUSTED GUARDIAN ACCESS"
      subtitle="Connect someone you trust to help monitor your security telemetry without exposing passwords or private messages."
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
        {/* Quick link to Guardian Chat */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(224, 197, 143, 0.08)', border: '1px solid rgba(224, 197, 143, 0.25)', padding: '14px 20px', borderRadius: '8px' }}>
          <div>
            <strong style={{ color: 'var(--kavach-swan-wing)', fontSize: '14px' }}>💬 Guardian Private Chat</strong>
            <p style={{ margin: '4px 0 0 0', fontSize: '12.5px', color: 'var(--kavach-shellstone)' }}>
              Direct private messaging and recorded voice notes with your linked guardian.
            </p>
          </div>
          <Link
            to="/user/guardian-chat"
            style={{
              background: 'var(--kavach-quicksand, #e0c58f)',
              color: 'var(--kavach-royal-blue, #0d1a3a)',
              padding: '8px 16px',
              borderRadius: '4px',
              fontWeight: 700,
              fontSize: '13px',
              textDecoration: 'none',
              whiteSpace: 'nowrap'
            }}
          >
            Open Guardian Chat →
          </Link>
        </div>

        {/* Guardian Code Generator Card */}
        <section className={styles.guardianPanel}>
          <div className={styles.sectionHeader}>
            <h3 className={styles.sectionTitle}>
              GUARDIAN <span className={styles.sectionTitleAccent}>PAIRING CODE</span>
            </h3>
            <span className={styles.sectionSubtitle}>Temporary 24-hour cryptographic token</span>
          </div>

          <p className={styles.guardianIntro}>
            Share temporary access with someone you trust (a family member, guardian, or cybersecurity advisor).
            Your guardian can monitor threat alerts and system safety telemetry to help you, but they can <strong>never</strong> view your private passwords, authentication tokens, or personal message transcripts.
          </p>

          {guardianCode ? (
            <div>
              <div className={styles.codeDisplayBox}>
                <div>
                  <span className={styles.codeLabel}>YOUR 6-DIGIT ACCESS CODE</span>
                  <div className={styles.codeDigits}>{guardianCode}</div>
                </div>
                <button type="button" className={styles.copyCodeBtn} onClick={handleCopyCode}>
                  {copied ? '✓ COPIED TO CLIPBOARD' : 'COPY ACCESS CODE'}
                </button>
              </div>

              <div className={styles.codeNotice}>
                Valid for: <strong>24 hours (Expires at {guardianExpiry})</strong>
              </div>
              <div style={{ fontSize: '12px', color: '#fca5a5', marginTop: '6px' }}>
                ⚠ Only share this temporary access code with someone you personally know and trust.
              </div>

              <div>
                <button type="button" className={styles.revokeCodeBtn} onClick={handleRevokeCode}>
                  Revoke Active Code
                </button>
              </div>
            </div>
          ) : (
            <div>
              {codeMsg && (
                <p
                  className={`${styles.codeStatusMsg} ${
                    codeError ? styles.codeMsgError : styles.codeMsgSuccess
                  }`}
                >
                  {codeMsg}
                </p>
              )}
              <button
                type="button"
                className={styles.generateCodeBtn}
                onClick={handleGenerateCode}
              >
                Generate 6-Digit Guardian Code
              </button>
            </div>
          )}
        </section>

        {/* Guardian Privacy & Protection Principles Card */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px' }}>
          <div className={styles.statCard}>
            <span className={styles.statLabel}>ZERO CREDENTIAL LEAKAGE</span>
            <h4 style={{ fontFamily: 'Space Grotesk', fontSize: '16px', margin: '6px 0', color: 'var(--kavach-swan-wing)' }}>
              Total Password Privacy
            </h4>
            <p style={{ fontSize: '12.5px', color: 'var(--kavach-shellstone)', lineHeight: 1.5, margin: 0 }}>
              Guardians never see passwords, PINs, or banking credentials. Only security threat levels are shared.
            </p>
          </div>

          <div className={styles.statCard}>
            <span className={styles.statLabel}>SANITIZED TELEMETRY</span>
            <h4 style={{ fontFamily: 'Space Grotesk', fontSize: '16px', margin: '6px 0', color: 'var(--kavach-swan-wing)' }}>
              Privacy-Filtered Alerts
            </h4>
            <p style={{ fontSize: '12.5px', color: 'var(--kavach-shellstone)', lineHeight: 1.5, margin: 0 }}>
              Incident reports and alerts sent to guardians redact personal conversation text and private attachment files.
            </p>
          </div>

          <div className={styles.statCard}>
            <span className={styles.statLabel}>INSTANT REVOCATION</span>
            <h4 style={{ fontFamily: 'Space Grotesk', fontSize: '16px', margin: '6px 0', color: 'var(--kavach-swan-wing)' }}>
              User-Controlled Access
            </h4>
            <p style={{ fontSize: '12.5px', color: 'var(--kavach-shellstone)', lineHeight: 1.5, margin: 0 }}>
              Codes expire automatically after 24 hours. You can also revoke active guardian sessions instantly at any time.
            </p>
          </div>
        </div>
      </div>
    </UserLayout>
  );
}
