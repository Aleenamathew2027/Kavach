import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminDashboard.module.css';

export default function AdminDashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const res = await api.getAdminDashboard();
        setData(res);
      } catch (err) {
        console.error('Error loading admin dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const totalScans = data?.total_scans ?? 0;
  const threatsDetected = data?.threats_detected ?? 0;
  const suspiciousCount = data?.suspicious_incidents ?? 0;
  const safeCount = data?.safe_scans ?? 0;
  const scansByType = data?.scans_by_type || { message: 0, link: 0, document: 0 };
  const recentScans = data?.recent_scans || [];

  return (
    <div className={styles.page}>
      <AdminNav adminEmail={data?.admin_email || 'admin@kavach.sec'} />

      <main className={styles.main}>
        {/* ── SOC HERO HEADER ── */}
        <section className={styles.heroSection}>
          <div>
            <div className={styles.badgeRow}>
              <span className={styles.socPill}>SECURITY OPERATIONS CENTER</span>
              <span className={styles.liveTag}>
                <span className={styles.liveDot} /> LIVE DATABASE TELEMETRY
              </span>
            </div>
            <h1 className={styles.heroHeading}>SYSTEM SECURITY COMMAND</h1>
            <p className={styles.heroSub}>
              Global monitoring across registered users, automated ML scam scans, and guardian protection channels.
            </p>
          </div>

          <div className={styles.quickLinks}>
            <Link to="/admin/security-events" className={styles.quickBtn}>
              ⚡ View Live Incidents →
            </Link>
            <Link to="/admin/reports" className={styles.quickBtnOutline}>
              📊 Analytics Reports →
            </Link>
          </div>
        </section>

        {/* ── TOP METRICS CARDS ── */}
        <section className={styles.metricsGrid}>
          <div className={styles.metricCard}>
            <div className={styles.metricTop}>
              <span className={styles.metricLabel}>TOTAL REGISTERED USERS</span>
              <span className={styles.cardIcon}>👥</span>
            </div>
            <div className={styles.metricValue}>{data?.total_users ?? 0}</div>
            <div className={styles.metricSub}>Active in PostgreSQL DB</div>
          </div>

          <div className={styles.metricCard}>
            <div className={styles.metricTop}>
              <span className={styles.metricLabel}>ACTIVE GUARDIAN LINKS</span>
              <span className={styles.cardIcon}>🛡️</span>
            </div>
            <div className={styles.metricValue}>{data?.active_guardian_links ?? 0}</div>
            <div className={styles.metricSub}>Authorized Family Passes</div>
          </div>

          <div className={styles.metricCard}>
            <div className={styles.metricTop}>
              <span className={styles.metricLabel}>TOTAL SECURITY SCANS</span>
              <span className={styles.cardIcon}>🔍</span>
            </div>
            <div className={styles.metricValue}>{totalScans}</div>
            <div className={styles.metricSub}>Across All Channels</div>
          </div>

          <div className={styles.metricCard} style={{ borderColor: 'rgba(239, 68, 68, 0.4)' }}>
            <div className={styles.metricTop}>
              <span className={styles.metricLabel} style={{ color: '#f87171' }}>HIGH-RISK THREATS</span>
              <span className={styles.cardIcon}>⚠</span>
            </div>
            <div className={styles.metricValue} style={{ color: '#ef4444' }}>
              {threatsDetected}
            </div>
            <div className={styles.metricSub}>Flagged by ML & Rules</div>
          </div>
        </section>

        {/* ── THREAT DISTRIBUTION BAR ── */}
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}>TELEMETRY CHANNEL BREAKDOWN</h2>
            <span className={styles.panelSub}>Distribution across detection engines</span>
          </div>

          <div className={styles.breakdownGrid}>
            <div className={styles.breakdownItem}>
              <span className={styles.bLabel}>Message Scam Detector (ML)</span>
              <span className={styles.bVal}>{scansByType.message} Scans</span>
            </div>
            <div className={styles.breakdownItem}>
              <span className={styles.bLabel}>Link Safety Checker</span>
              <span className={styles.bVal}>{scansByType.link} Scans</span>
            </div>
            <div className={styles.breakdownItem}>
              <span className={styles.bLabel}>Document Scanner</span>
              <span className={styles.bVal}>{scansByType.document} Scans</span>
            </div>
          </div>
        </section>

        {/* ── RECENT SECURITY EVENTS TABLE ── */}
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <div>
              <h2 className={styles.panelTitle}>RECENT SECURITY SCAN INCIDENTS</h2>
              <span className={styles.panelSub}>Latest safety evaluations from database</span>
            </div>
            <Link to="/admin/security-events" className={styles.panelLink}>
              View All Security Events →
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className={styles.emptyTable}>No security scans logged yet.</div>
          ) : (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>SCAN ID</th>
                    <th>CHANNEL</th>
                    <th>TARGET / PREVIEW</th>
                    <th>RISK LEVEL</th>
                    <th>SCORE</th>
                    <th>TIMESTAMP</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((s) => {
                    const isHigh = s.risk_level === 'HIGH RISK';
                    const isSuspicious = s.risk_level === 'SUSPICIOUS';
                    return (
                      <tr key={s.id}>
                        <td className={styles.monoCell}>#{s.id}</td>
                        <td>
                          <span className={styles.typeTag}>{s.scan_type.toUpperCase()}</span>
                        </td>
                        <td className={styles.previewCell}>{s.input_reference}</td>
                        <td>
                          <span
                            className={
                              isHigh
                                ? styles.badgeHigh
                                : isSuspicious
                                ? styles.badgeMed
                                : styles.badgeSafe
                            }
                          >
                            {s.risk_level}
                          </span>
                        </td>
                        <td className={styles.scoreCell}>{s.risk_score}/100</td>
                        <td className={styles.timeCell}>
                          {s.created_at
                            ? new Date(s.created_at).toLocaleString([], {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                              })
                            : 'Just now'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
