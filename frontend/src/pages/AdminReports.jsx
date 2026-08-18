import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminReports.module.css';

export default function AdminReports() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReports() {
      setLoading(true);
      try {
        const data = await api.getAdminReports();
        setReport(data);
      } catch (err) {
        console.error('Error loading reports:', err);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const totalScans = report?.total_scans ?? 0;
  const threatsDetected = report?.threats_detected ?? 0;
  const safeScans = report?.safe_count ?? 0;
  const safetyRate = report?.safety_rate ?? 100.0;
  const threatsByType = report?.threats_by_type || { message: 0, link: 0, document: 0 };
  const scansByType = report?.scans_by_type || { message: 0, link: 0, document: 0 };

  return (
    <div className={styles.page}>
      <AdminNav />

      <main className={styles.main}>
        <div>
          <Link to="/admin/dashboard" className={styles.backLink}>
            ← Back to SOC Dashboard
          </Link>
        </div>

        <div className={styles.header}>
          <div>
            <span className={styles.sectionPill}>SECURITY ANALYTICS</span>
            <h1 className={styles.title}>THREAT INTELLIGENCE REPORTS</h1>
            <p className={styles.subtitle}>
              Aggregate statistics, safety indices, and multi-channel scam interception trends.
            </p>
          </div>

          <div className={styles.healthTag}>
            <span className={styles.healthDot} />
            OVERALL SAFETY INDEX: <strong>{safetyRate}%</strong>
          </div>
        </div>

        {/* ── HIGH-LEVEL SUMMARY METRICS ── */}
        <section className={styles.summaryGrid}>
          <div className={styles.summaryCard}>
            <span className={styles.cardLabel}>TOTAL SCANS EXECUTED</span>
            <span className={styles.cardVal}>{totalScans}</span>
            <span className={styles.cardSub}>Database telemetry</span>
          </div>

          <div className={styles.summaryCard}>
            <span className={styles.cardLabel}>HIGH-RISK THREATS INTERCEPTED</span>
            <span className={styles.cardVal} style={{ color: threatsDetected > 0 ? '#ef4444' : '#3fb950' }}>
              {threatsDetected}
            </span>
            <span className={styles.cardSub}>Scam & Phishing patterns</span>
          </div>

          <div className={styles.summaryCard}>
            <span className={styles.cardLabel}>VERIFIED SAFE COMMUNICATIONS</span>
            <span className={styles.cardVal} style={{ color: '#3fb950' }}>
              {safeScans}
            </span>
            <span className={styles.cardSub}>Clean verdicts</span>
          </div>

          <div className={styles.summaryCard}>
            <span className={styles.cardLabel}>ACTIVE GUARDIAN BRIDGES</span>
            <span className={styles.cardVal} style={{ color: '#00e5ff' }}>
              {report?.active_guardians ?? 0}
            </span>
            <span className={styles.cardSub}>Family protection networks</span>
          </div>
        </section>

        {/* ── THREATS BY ATTACK VECTOR ── */}
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}>THREATS BY ATTACK VECTOR</h2>
            <span className={styles.panelSub}>High-risk detections per security module</span>
          </div>

          <div className={styles.barsGrid}>
            <div className={styles.barItem}>
              <div className={styles.barTop}>
                <span className={styles.barTitle}>Message Scam Detector (SMS / Email / Chat)</span>
                <span className={styles.barCount}>{threatsByType.message} Threats</span>
              </div>
              <div className={styles.barTrack}>
                <div
                  className={styles.barFillDanger}
                  style={{ width: `${totalScans > 0 ? (threatsByType.message / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div className={styles.barItem}>
              <div className={styles.barTop}>
                <span className={styles.barTitle}>Malicious & Phishing URL Scanner</span>
                <span className={styles.barCount}>{threatsByType.link} Threats</span>
              </div>
              <div className={styles.barTrack}>
                <div
                  className={styles.barFillDanger}
                  style={{ width: `${totalScans > 0 ? (threatsByType.link / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div className={styles.barItem}>
              <div className={styles.barTop}>
                <span className={styles.barTitle}>Deceptive Document & Attachment Scanner</span>
                <span className={styles.barCount}>{threatsByType.document} Threats</span>
              </div>
              <div className={styles.barTrack}>
                <div
                  className={styles.barFillDanger}
                  style={{ width: `${totalScans > 0 ? (threatsByType.document / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </section>

        {/* ── TOTAL VOLUME BY CHANNEL ── */}
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}>TOTAL SCAN VOLUME BY CHANNEL</h2>
            <span className={styles.panelSub}>Usage telemetry across protection tools</span>
          </div>

          <div className={styles.volumeGrid}>
            <div className={styles.volumeBox}>
              <span className={styles.volIcon}>💬</span>
              <div>
                <strong>Messages Scanned</strong>
                <span>{scansByType.message} Total Verifications</span>
              </div>
            </div>

            <div className={styles.volumeBox}>
              <span className={styles.volIcon}>🔗</span>
              <div>
                <strong>Links Inspected</strong>
                <span>{scansByType.link} Total Verifications</span>
              </div>
            </div>

            <div className={styles.volumeBox}>
              <span className={styles.volIcon}>📄</span>
              <div>
                <strong>Documents Checked</strong>
                <span>{scansByType.document} Total Verifications</span>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
