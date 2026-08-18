import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import GuardianNav from '../components/GuardianNav';
import styles from './GuardianActivity.module.css';

export default function GuardianActivity() {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [userProfile, setUserProfile] = useState(null);

  useEffect(() => {
    async function loadActivity() {
      setLoading(true);
      try {
        const [actList, gDash] = await Promise.all([
          api.getGuardianActivity().catch(() => []),
          api.getGuardianDashboard().catch(() => null),
        ]);
        setActivities(actList || []);
        if (gDash?.guarded_user) {
          setUserProfile(gDash.guarded_user);
        }
      } catch (err) {
        console.error('Error loading guardian activity:', err);
      } finally {
        setLoading(false);
      }
    }
    loadActivity();
  }, []);

  return (
    <div className={styles.page}>
      <GuardianNav
        guardianName="Authorized Guardian"
        protectedUserName={userProfile?.full_name || 'Protected User'}
      />

      <main className={styles.main}>
        <div>
          <Link to="/guardian/dashboard" className={styles.backLink}>
            ← Back to Guardian Overview
          </Link>
        </div>

        <div className={styles.header}>
          <span className={styles.sectionPill}>AUDIT TIMELINE</span>
          <h1 className={styles.title}>GUARDIAN SECURITY ACTIVITY</h1>
          <p className={styles.subtitle}>
            Privacy-safe chronological verification log for {userProfile?.full_name || 'your protected user'}.
          </p>
        </div>

        {/* ── ACTIVITY TIMELINE ── */}
        <section className={styles.timelineCard}>
          {loading ? (
            <div className={styles.emptyState}>Loading activity telemetry…</div>
          ) : activities.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>📋</span>
              <h3>No Activity Recorded Yet</h3>
              <p>When your protected user scans messages, links, or documents, safety event timestamps will appear here.</p>
            </div>
          ) : (
            <div className={styles.timelineList}>
              {activities.map((item) => {
                const isHigh = item.risk_level === 'HIGH RISK';
                const isSuspicious = item.risk_level === 'SUSPICIOUS';

                return (
                  <div key={item.id} className={styles.timelineRow}>
                    <div
                      className={styles.timelineDot}
                      style={
                        isHigh
                          ? { background: '#ef4444' }
                          : isSuspicious
                          ? { background: '#f59e0b' }
                          : { background: '#48e5c2' }
                      }
                    />

                    <div className={styles.timelineContent}>
                      <div className={styles.contentTop}>
                        <h3 className={styles.eventTitle}>{item.event}</h3>
                        <span
                          className={
                            isHigh
                              ? styles.badgeHigh
                              : isSuspicious
                              ? styles.badgeMed
                              : styles.badgeSafe
                          }
                        >
                          {item.risk_level}
                        </span>
                      </div>

                      <p className={styles.summaryText}>{item.summary || 'Content verified against threat patterns.'}</p>

                      <div className={styles.metaRow}>
                        <span className={styles.timeText}>
                          {item.time
                            ? new Date(item.time).toLocaleString([], {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                              })
                            : 'Logged just now'}
                        </span>
                        <span className={styles.privacyNote}>🔒 Private Content Preserved</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
