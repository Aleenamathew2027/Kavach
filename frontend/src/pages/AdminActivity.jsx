import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminActivity.module.css';

export default function AdminActivity() {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadActivity() {
      setLoading(true);
      try {
        const data = await api.getAdminActivity();
        setActivities(data || []);
      } catch (err) {
        console.error('Error loading admin activity:', err);
      } finally {
        setLoading(false);
      }
    }
    loadActivity();
  }, []);

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
            <span className={styles.sectionPill}>SYSTEM EVENT LOG</span>
            <h1 className={styles.title}>AUDIT & SYSTEM ACTIVITY</h1>
            <p className={styles.subtitle}>
              Real-time audit log of user scans, threat alerts, and automated security triggers.
            </p>
          </div>
        </div>

        {/* ── ACTIVITY TIMELINE PANEL ── */}
        <section className={styles.timelinePanel}>
          {loading ? (
            <div className={styles.emptyState}>Loading activity log from PostgreSQL…</div>
          ) : activities.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>📋</span>
              <h3>No system events logged yet</h3>
              <p>Security scan executions and alerts will be logged chronologically here.</p>
            </div>
          ) : (
            <div className={styles.timelineList}>
              {activities.map((act) => {
                const isHigh = act.severity === 'HIGH' || act.severity === 'HIGH RISK';
                const isAlert = act.type === 'SECURITY_ALERT';

                return (
                  <div key={act.id} className={styles.timelineItem}>
                    <div
                      className={styles.timelineDot}
                      style={{ background: isHigh ? '#ef4444' : isAlert ? '#f59e0b' : '#00e5ff' }}
                    />

                    <div className={styles.timelineCard}>
                      <div className={styles.cardHeader}>
                        <div className={styles.headerLeft}>
                          <span className={styles.typeBadge}>
                            {act.type.replace('_', ' ')}
                          </span>
                          <h3 className={styles.eventTitle}>{act.title}</h3>
                        </div>
                        <span
                          className={
                            isHigh
                              ? styles.badgeHigh
                              : act.severity === 'SUSPICIOUS'
                              ? styles.badgeMed
                              : styles.badgeSafe
                          }
                        >
                          {act.severity || 'INFO'}
                        </span>
                      </div>

                      <p className={styles.eventDetail}>{act.detail}</p>

                      <span className={styles.timestamp}>
                        {act.created_at
                          ? new Date(act.created_at).toLocaleString([], {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit',
                            })
                          : 'Logged just now'}
                      </span>
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
