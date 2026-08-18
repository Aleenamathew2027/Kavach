import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import GuardianNav from '../components/GuardianNav';
import styles from './GuardianProtectedUser.module.css';

export default function GuardianProtectedUser() {
  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getGuardianDashboard();
        setGuardianData(data);
      } catch (err) {
        console.error('Error loading guarded user profile:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const user = guardianData?.guarded_user || { full_name: 'Protected User', email: 'user@kavach.sec' };
  const stats = guardianData?.security_summary || { threats_detected: 0, suspicious_messages: 0, suspicious_links: 0, suspicious_documents: 0 };
  const isAttentionRequired = guardianData?.overall_status === 'ATTENTION REQUIRED';
  const totalScans = stats.threats_detected + stats.suspicious_messages + stats.suspicious_links + stats.suspicious_documents;

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
          <span className={styles.sectionPill}>PRIVACY-SAFE IDENTITY</span>
          <h1 className={styles.title}>PROTECTED USER PROFILE</h1>
          <p className={styles.subtitle}>
            Verified security status and account telemetry for the family member you are protecting.
          </p>
        </div>

        {/* ── USER OVERVIEW CARD ── */}
        <section className={styles.profileCard}>
          <div className={styles.avatarRow}>
            <div className={styles.avatar}>
              {user.full_name ? user.full_name.charAt(0).toUpperCase() : 'U'}
            </div>
            <div>
              <h2 className={styles.personName}>{user.full_name}</h2>
              <span className={styles.personEmail}>{user.email}</span>
            </div>
            <div className={styles.statusBadge}>
              <span className={styles.statusDot} style={isAttentionRequired ? { background: '#ef4444' } : {}} />
              {isAttentionRequired ? 'ATTENTION REQUIRED' : 'PROTECTED'}
            </div>
          </div>

          <div className={styles.fieldsGrid}>
            <div className={styles.fieldBox}>
              <span className={styles.fieldLabel}>PROTECTION STATUS</span>
              <span className={isAttentionRequired ? styles.fieldValDanger : styles.fieldValSuccess}>
                {isAttentionRequired ? 'HIGH RISK DETECTED' : 'SECURE & PROTECTED'}
              </span>
            </div>

            <div className={styles.fieldBox}>
              <span className={styles.fieldLabel}>ACCOUNT ROLE</span>
              <span className={styles.fieldVal}>KAVACH STANDARD USER</span>
            </div>

            <div className={styles.fieldBox}>
              <span className={styles.fieldLabel}>ACCOUNT STATUS</span>
              <span className={styles.fieldVal}>ACTIVE & VERIFIED</span>
            </div>

            <div className={styles.fieldBox}>
              <span className={styles.fieldLabel}>TOTAL SCANS PERFORMED</span>
              <span className={styles.fieldVal}>{totalScans} Safety Verifications</span>
            </div>
          </div>
        </section>

        {/* ── PRIVACY NOTICE ── */}
        <section className={styles.privacyCard}>
          <div className={styles.privacyHeader}>
            <span style={{ fontSize: '20px' }}>🔒</span>
            <strong>Privacy Protection Guarantee</strong>
          </div>
          <p className={styles.privacyText}>
            Under KAVACH Privacy Protocols, guardians receive real-time threat alerts, severity assessments, and guidance. Passwords, personal message texts, and private files are never exposed.
          </p>
        </section>

        {/* ── QUICK ACTION LINKS ── */}
        <section className={styles.actionsGrid}>
          <Link to="/guardian/alerts" className={styles.actionCard}>
            <h3>View Security Alerts →</h3>
            <p>Review flagged incidents and safety recommendations.</p>
          </Link>
          <Link to="/guardian/security" className={styles.actionCard}>
            <h3>View Security Telemetry →</h3>
            <p>Analyze threat distribution across messages and links.</p>
          </Link>
          <Link to="/guardian/activity" className={styles.actionCard}>
            <h3>View Activity Log →</h3>
            <p>Inspect recent privacy-safe scan timestamps.</p>
          </Link>
        </section>
      </main>
    </div>
  );
}
