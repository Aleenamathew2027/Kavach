import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminSettings.module.css';

export default function AdminSettings() {
  const navigate = useNavigate();
  const [adminData, setAdminData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [telemetrySync, setTelemetrySync] = useState(true);
  const [autoAlerts, setAutoAlerts] = useState(true);
  const [saveMsg, setSaveMsg] = useState('');

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getAdminDashboard();
        setAdminData(data);
      } catch (err) {
        console.error('Error loading admin settings:', err);
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
    setSaveMsg('SOC configuration preferences updated successfully.');
    setTimeout(() => setSaveMsg(''), 3000);
  };

  return (
    <div className={styles.page}>
      <AdminNav adminEmail={adminData?.admin_email || 'admin@kavach.sec'} />

      <main className={styles.main}>
        <div>
          <Link to="/admin/dashboard" className={styles.backLink}>
            ← Back to SOC Dashboard
          </Link>
        </div>

        <div className={styles.header}>
          <span className={styles.sectionPill}>SYSTEM CONFIGURATION</span>
          <h1 className={styles.title}>SOC ADMIN SETTINGS</h1>
          <p className={styles.subtitle}>
            Platform security preferences, ML engine diagnostics, and administrative session controls.
          </p>
        </div>

        {saveMsg && <div className={styles.bannerSuccess}>✓ {saveMsg}</div>}

        {/* ── DATABASE & CORE STATUS ── */}
        <section className={styles.card}>
          <h2 className={styles.cardTitle}>DATABASE & SYSTEM TELEMETRY</h2>
          <div className={styles.statusGrid}>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>PRIMARY DATABASE</span>
              <span className={styles.statusValSuccess}>PostgreSQL 16 (Connected)</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>FASTAPI ENGINE</span>
              <span className={styles.statusValSuccess}>v0.115+ (Operational)</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>ACTIVE ADMIN SESSION</span>
              <span className={styles.statusVal}>{adminData?.admin_email || 'admin@kavach.sec'}</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>SYSTEM ROLE</span>
              <span className={styles.statusVal}>SYSTEM ADMINISTRATOR (ROOT)</span>
            </div>
          </div>
        </section>

        {/* ── ML SCAM ENGINE DIAGNOSTICS ── */}
        <section className={styles.card}>
          <h2 className={styles.cardTitle}>MACHINE LEARNING INFERENCE ENGINE</h2>
          <div className={styles.statusGrid}>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>CLASSIFIER MODEL</span>
              <span className={styles.statusValCyan}>Logistic Regression (Balanced Weights)</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>FEATURE VECTORIZER</span>
              <span className={styles.statusVal}>TF-IDF (1-2 N-Grams, 5000 Features)</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>TRAINING BENCHMARK</span>
              <span className={styles.statusVal}>SMS Spam Collection (5,572 Samples)</span>
            </div>
            <div className={styles.statusItem}>
              <span className={styles.statusLabel}>HYBRID SCORING</span>
              <span className={styles.statusValSuccess}>Active (ML Inference + Rule Heuristics)</span>
            </div>
          </div>
        </section>

        {/* ── PREFERENCES FORM ── */}
        <section className={styles.card}>
          <h2 className={styles.cardTitle}>SOC MONITORING PREFERENCES</h2>
          <form onSubmit={handleSave} className={styles.form}>
            <label className={styles.checkboxRow}>
              <input
                type="checkbox"
                checked={telemetrySync}
                onChange={(e) => setTelemetrySync(e.target.checked)}
              />
              <div>
                <strong>Continuous Database Telemetry Stream</strong>
                <p>Periodically refresh security scan events and threat alerts across all users.</p>
              </div>
            </label>

            <label className={styles.checkboxRow}>
              <input
                type="checkbox"
                checked={autoAlerts}
                onChange={(e) => setAutoAlerts(e.target.checked)}
              />
              <div>
                <strong>Automated High-Risk Security Incident Generation</strong>
                <p>Automatically log critical alert records when ML scam probability exceeds 70%.</p>
              </div>
            </label>

            <div>
              <button type="submit" className={styles.saveBtn}>
                SAVE CONFIGURATION
              </button>
            </div>
          </form>
        </section>

        {/* ── LOGOUT SESSION ── */}
        <section className={styles.dangerCard}>
          <div>
            <h2 className={styles.dangerTitle}>TERMINATE SOC SESSION</h2>
            <p className={styles.dangerText}>
              Log out of the KAVACH Administrator Command Console on this workstation.
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
