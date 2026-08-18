import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import GuardianNav from '../components/GuardianNav';
import styles from './GuardianSecurity.module.css';

export default function GuardianSecurity() {
  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getGuardianDashboard();
        setGuardianData(data);
      } catch (err) {
        console.error('Error loading guardian security page:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const user = guardianData?.guarded_user || { full_name: 'Protected User' };
  const stats = guardianData?.security_summary || {
    threats_detected: 0,
    suspicious_messages: 0,
    suspicious_links: 0,
    suspicious_documents: 0,
  };
  const isAttentionRequired = guardianData?.overall_status === 'ATTENTION REQUIRED';

  return (
    <div className={styles.page}>
      <GuardianNav
        guardianName="Authorized Guardian"
        protectedUserName={user.full_name}
      />

      <main className={styles.main}>
        <div>
          <Link to="/guardian/dashboard" className={styles.backLink}>
            ← Back to Guardian Overview
          </Link>
        </div>

        <div className={styles.header}>
          <span className={styles.sectionPill}>SECURITY TELEMETRY</span>
          <h1 className={styles.title}>PROTECTION MODULES & STATS</h1>
          <p className={styles.subtitle}>
            Continuous threat analysis across communication channels for {user.full_name}.
          </p>
        </div>

        {/* ── STATUS OVERVIEW ── */}
        <section
          className={styles.statusPanel}
          style={isAttentionRequired ? { borderColor: '#ef4444', background: '#1c1012' } : {}}
        >
          <div className={styles.statusTop}>
            <div>
              <span className={styles.statusLabel}>OVERALL SECURITY STATUS</span>
              <h2 className={styles.statusTitle}>
                {isAttentionRequired ? '⚠ ATTENTION REQUIRED' : '✓ FULLY PROTECTED'}
              </h2>
            </div>
            <span className={isAttentionRequired ? styles.badgeDanger : styles.badgeSuccess}>
              {isAttentionRequired ? 'ACTIVE THREATS' : 'NORMAL TELEMETRY'}
            </span>
          </div>
          <p className={styles.statusDesc}>
            {isAttentionRequired
              ? `${stats.threats_detected} high-risk scam pattern(s) have been intercepted. Please verify with the user.`
              : 'All security scanners report healthy telemetry. No deceptive financial links or phishing messages detected.'}
          </p>
        </section>

        {/* ── DETAILED THREAT BREAKDOWN ── */}
        <section className={styles.modulesGrid}>
          {/* Message Scam Detector */}
          <div className={styles.moduleCard}>
            <div className={styles.modTop}>
              <span className={styles.modTag}>AI SCAM CLASSIFIER</span>
              <span className={styles.modStatus}>ACTIVE</span>
            </div>
            <h3 className={styles.modTitle}>Message Scam Filter</h3>
            <p className={styles.modDesc}>
              Scans incoming SMS, email, and chat messages for urgency, OTP harvesting, and banking fraud.
            </p>
            <div className={styles.metricRow}>
              <span className={styles.metricLabel}>Suspicious Messages:</span>
              <span className={styles.metricVal}>{stats.suspicious_messages}</span>
            </div>
          </div>

          {/* Link Safety Checker */}
          <div className={styles.moduleCard}>
            <div className={styles.modTop}>
              <span className={styles.modTag}>WEB SAFETY</span>
              <span className={styles.modStatus}>ACTIVE</span>
            </div>
            <h3 className={styles.modTitle}>Malicious URL Checker</h3>
            <p className={styles.modDesc}>
              Detects typosquatting, deceptive domain masks, and credential harvesting portals.
            </p>
            <div className={styles.metricRow}>
              <span className={styles.metricLabel}>Suspicious Links:</span>
              <span className={styles.metricVal}>{stats.suspicious_links}</span>
            </div>
          </div>

          {/* Document Scanner */}
          <div className={styles.moduleCard}>
            <div className={styles.modTop}>
              <span className={styles.modTag}>FILE INTEGRITY</span>
              <span className={styles.modStatus}>ACTIVE</span>
            </div>
            <h3 className={styles.modTitle}>Document Scanner</h3>
            <p className={styles.modDesc}>
              Analyzes PDF, DOCX, and TXT files for fraudulent invoice notices and extortion text.
            </p>
            <div className={styles.metricRow}>
              <span className={styles.metricLabel}>Suspicious Documents:</span>
              <span className={styles.metricVal}>{stats.suspicious_documents}</span>
            </div>
          </div>

          {/* Voice Scam Analyzer */}
          <div className={styles.moduleCard} style={{ opacity: 0.85 }}>
            <div className={styles.modTop}>
              <span className={styles.modTag}>AUDIO FIREWALL</span>
              <span className={styles.modStatusSoon}>PLANNED</span>
            </div>
            <h3 className={styles.modTitle}>Deepfake Voice Analyzer</h3>
            <p className={styles.modDesc}>
              AI synthesis detection for caller voice authenticity and impersonation attempts.
            </p>
            <div className={styles.metricRow}>
              <span className={styles.metricLabel}>Status:</span>
              <span className={styles.metricValMuted}>Not available yet</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
