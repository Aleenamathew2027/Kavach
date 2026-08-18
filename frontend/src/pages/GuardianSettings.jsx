import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import GuardianNav from '../components/GuardianNav';
import styles from './GuardianSettings.module.css';

export default function GuardianSettings() {
  const navigate = useNavigate();
  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [highRiskAlertsOnly, setHighRiskAlertsOnly] = useState(false);
  const [browserNotifications, setBrowserNotifications] = useState(true);
  const [saveMsg, setSaveMsg] = useState('');

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getGuardianDashboard();
        setGuardianData(data);
      } catch (err) {
        console.error('Error loading guardian settings:', err);
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

  const handleSave = (e) => {
    e.preventDefault();
    setSaveMsg('Preferences saved successfully for this session.');
    setTimeout(() => setSaveMsg(''), 3000);
  };

  const protectedUser = guardianData?.guarded_user || { full_name: 'Protected User', email: '—' };
  const authUntil = guardianData?.authorized_until
    ? new Date(guardianData.authorized_until).toLocaleString([], {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '24-Hour Active Session';

  return (
    <div className={styles.page}>
      <GuardianNav
        guardianName="Authorized Guardian"
        protectedUserName={protectedUser.full_name}
      />

      <main className={styles.main}>
        <div>
          <Link to="/guardian/dashboard" className={styles.backLink}>
            ← Back to Guardian Overview
          </Link>
        </div>

        <div className={styles.header}>
          <span className={styles.sectionPill}>GUARDIAN PREFERENCES</span>
          <h1 className={styles.title}>GUARDIAN SETTINGS</h1>
          <p className={styles.subtitle}>
            Manage your guardian authorization session, alert thresholds, and security preferences.
          </p>
        </div>

        {saveMsg && <div className={styles.bannerSuccess}>✓ {saveMsg}</div>}

        {/* ── AUTHORIZATION DETAILS ── */}
        <section className={styles.card}>
          <h2 className={styles.cardTitle}>GUARDIAN AUTHORIZATION STATUS</h2>
          <div className={styles.infoGrid}>
            <div className={styles.infoBox}>
              <span className={styles.infoLabel}>PROTECTED USER</span>
              <span className={styles.infoVal}>{protectedUser.full_name} ({protectedUser.email})</span>
            </div>
            <div className={styles.infoBox}>
              <span className={styles.infoLabel}>AUTHORIZATION ACCESS</span>
              <span className={styles.infoValSuccess}>ACTIVE & VERIFIED</span>
            </div>
            <div className={styles.infoBox}>
              <span className={styles.infoLabel}>PASS VALID UNTIL</span>
              <span className={styles.infoVal}>{authUntil}</span>
            </div>
            <div className={styles.infoBox}>
              <span className={styles.infoLabel}>SECURITY CLEARANCE</span>
              <span className={styles.infoVal}>Real-time Threat Interceptions</span>
            </div>
          </div>
        </section>

        {/* ── NOTIFICATION PREFERENCES ── */}
        <section className={styles.card}>
          <h2 className={styles.cardTitle}>ALERT & TELEMETRY PREFERENCES</h2>
          <form onSubmit={handleSave} className={styles.settingsForm}>
            <label className={styles.checkboxRow}>
              <input
                type="checkbox"
                checked={browserNotifications}
                onChange={(e) => setBrowserNotifications(e.target.checked)}
              />
              <div>
                <strong>In-App High-Risk Alert Modals</strong>
                <p>Display emergency popup notifications when a critical phishing or financial scam is flagged.</p>
              </div>
            </label>

            <label className={styles.checkboxRow}>
              <input
                type="checkbox"
                checked={highRiskAlertsOnly}
                onChange={(e) => setHighRiskAlertsOnly(e.target.checked)}
              />
              <div>
                <strong>High-Risk Threats Only</strong>
                <p>Filter out low/medium telemetry and only surface verified critical threats.</p>
              </div>
            </label>

            <div style={{ marginTop: '10px' }}>
              <button type="submit" className={styles.saveBtn}>
                SAVE PREFERENCES
              </button>
            </div>
          </form>
        </section>

        {/* ── SESSION TERMINATION ── */}
        <section className={styles.dangerCard}>
          <div>
            <h2 className={styles.dangerTitle}>TERMINATE GUARDIAN SESSION</h2>
            <p className={styles.dangerText}>
              Log out of the Guardian console on this device. You will need a new 6-digit access code to log back in.
            </p>
          </div>
          <button className={styles.logoutBtn} onClick={handleLogout}>
            LOGOUT NOW
          </button>
        </section>
      </main>
    </div>
  );
}
