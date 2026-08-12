import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import styles from './GuardianDashboard.module.css';

export default function GuardianDashboard() {
  const navigate = useNavigate();

  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getGuardianDashboard();
        setGuardianData(data);
      } catch (err) {
        console.error('Error loading guardian dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const protectedName = guardianData?.guarded_user?.full_name || 'Protected User';
  const expiryFormatted = guardianData?.authorized_until
    ? new Date(guardianData.authorized_until).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
    : '24-Hour Pass Active';

  const isAttentionRequired = guardianData?.overall_status === 'ATTENTION REQUIRED';
  const stats = guardianData?.security_summary || {
    threats_detected: 0,
    suspicious_messages: 0,
    suspicious_links: 0,
    suspicious_documents: 0,
  };

  const alerts = guardianData?.recent_alerts || [];

  return (
    <div className={styles.page}>
      {/* ── HEADER ── */}
      <header className={styles.header}>
        <div className={styles.headerContainer}>
          <div className={styles.logoArea}>
            <span className={styles.logoText}>KAVACH</span>
            <span className={styles.guardianTag}>GUARDIAN PORTAL</span>
          </div>

          <div className={styles.headerRight}>
            <div className={styles.liveIndicator}>
              <span className={styles.indicatorDot} />
              PROTECTION ACTIVE
            </div>
            <button className={styles.logoutBtn} onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* ── MAIN CONTENT ── */}
      <main className={styles.main}>
        {/* ── HERO SECTION ── */}
        <section className={styles.heroSection}>
          <h1 className={styles.heroHeading}>
            PROTECTION<br />
            OVERVIEW.
          </h1>
          <p className={styles.heroSubtitle}>
            Stay informed about the safety of the person you are protecting.
          </p>
        </section>

        {/* ── DUAL HERO CARDS ── */}
        <section className={styles.dualCards}>
          {/* Protected Person Card */}
          <div className={styles.protectedPersonCard}>
            <div>
              <span className={styles.cardHeaderLabel}>PROTECTED PERSON</span>
              <div className={styles.personInfo} style={{ marginTop: '16px' }}>
                <div className={styles.personAvatar}>
                  {protectedName.charAt(0).toUpperCase()}
                </div>
                <div>
                  <div className={styles.personName}>{protectedName}</div>
                  <div className={styles.personRole}>Role: Protected Family Member</div>
                </div>
              </div>
            </div>

            <div className={styles.cardFooterInfo}>
              <span>
                Status:{' '}
                <strong style={{ color: isAttentionRequired ? '#dc2626' : '#166534' }}>
                  {isAttentionRequired ? 'ATTENTION REQUIRED' : 'SAFE'}
                </strong>
              </span>
              <span>Valid: {expiryFormatted}</span>
            </div>
          </div>

          {/* Safety Status Card */}
          <div
            className={styles.safetyStatusCard}
            style={isAttentionRequired ? { background: '#451a03', borderColor: '#78350f' } : {}}
          >
            <div className={styles.safetyStatusLabel}>CURRENT STATUS</div>
            <div className={styles.safetyMain}>
              <div className={styles.safetyTitle}>
                {isAttentionRequired ? 'ATTENTION REQUIRED' : 'SAFE'}
              </div>
              <p className={styles.safetySub}>
                {isAttentionRequired
                  ? `${stats.threats_detected} scam threat(s) flagged for your protected user.`
                  : '"No immediate threats detected."'}
              </p>
            </div>
            <div className={styles.safetyFooter}>
              <span>Continuous Telemetry</span>
              <span>Privacy Preserved: No Message Content Stored</span>
            </div>
          </div>
        </section>

        {/* ── LIVE SECURITY SUMMARY ── */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '18px' }}>
          <div style={{ background: '#ffffff', border: '1px solid #ebe5dc', padding: '24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '1px', color: '#78716c' }}>THREATS DETECTED</span>
            <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '32px', fontWeight: 800, color: isAttentionRequired ? '#dc2626' : '#1c1917' }}>
              {stats.threats_detected}
            </span>
          </div>

          <div style={{ background: '#ffffff', border: '1px solid #ebe5dc', padding: '24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '1px', color: '#78716c' }}>SUSPICIOUS MESSAGES</span>
            <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '32px', fontWeight: 800, color: '#1c1917' }}>
              {stats.suspicious_messages}
            </span>
          </div>

          <div style={{ background: '#ffffff', border: '1px solid #ebe5dc', padding: '24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '1px', color: '#78716c' }}>SUSPICIOUS LINKS</span>
            <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '32px', fontWeight: 800, color: '#1c1917' }}>
              {stats.suspicious_links}
            </span>
          </div>

          <div style={{ background: '#ffffff', border: '1px solid #ebe5dc', padding: '24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '1px', color: '#78716c' }}>SUSPICIOUS DOCUMENTS</span>
            <span style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '32px', fontWeight: 800, color: '#1c1917' }}>
              {stats.suspicious_documents}
            </span>
          </div>
        </section>

        {/* ── RECENT ALERTS SECTION ── */}
        <section className={styles.alertsSection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>RECENT GUARDIAN SECURITY ALERTS</h2>
            <span style={{ fontSize: '12px', color: '#78716c' }}>Authorized high-level privacy telemetry</span>
          </div>

          {alerts.length === 0 ? (
            <div style={{ padding: '28px', textAlign: 'center', color: '#78716c', fontSize: '14px' }}>
              No critical alerts. Your protected family member's scans are currently normal.
            </div>
          ) : (
            <div className={styles.alertList}>
              {alerts.map((alt) => (
                <div key={alt.id} className={styles.alertRow}>
                  <div className={styles.alertLeft}>
                    <span className={styles.alertEvent}>{alt.title}</span>
                    <span className={styles.alertTime}>
                      {new Date(alt.time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </span>
                    <span style={{ fontSize: '12.5px', color: '#b45309', marginTop: '4px' }}>
                      ⚡ Recommended Action: {alt.recommended_action}
                    </span>
                  </div>
                  <span className={styles.alertBadge} style={{ background: alt.severity === 'HIGH' ? '#fee2e2' : '#fef3c7', color: alt.severity === 'HIGH' ? '#991b1b' : '#92400e' }}>
                    {alt.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── EMERGENCY & HELP GUIDANCE ── */}
        <section className={styles.emergencyCard}>
          <h2 className={styles.emergencyTitle}>EMERGENCY SAFETY GUIDANCE</h2>
          <p className={styles.emergencyText}>
            If you suspect the protected user is facing an urgent phone scam or deceptive security threat, follow these standard protective steps:
          </p>

          <div className={styles.stepGrid}>
            <div className={styles.stepBlock}>
              <span className={styles.stepNum}>STEP 01</span>
              <strong>Stop Transaction Approvals</strong>
              <span>Instruct them never to share OTPs, PINs, or confirm unexpected bank transfers over the phone.</span>
            </div>

            <div className={styles.stepBlock}>
              <span className={styles.stepNum}>STEP 02</span>
              <strong>Disconnect Unknown Calls</strong>
              <span>Advise them to hang up and verify directly with the official institution or trusted family.</span>
            </div>

            <div className={styles.stepBlock}>
              <span className={styles.stepNum}>STEP 03</span>
              <strong>Verify With Kavach</strong>
              <span>Check the latest security scan results and report fraudulent numbers to security authorities.</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
