import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import GuardianLayout from '../components/GuardianLayout';
import styles from './GuardianAlerts.module.css';

export default function GuardianAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');
  const [userProfile, setUserProfile] = useState(null);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const [alertList, gDash] = await Promise.all([
        api.getGuardianAlerts().catch(() => []),
        api.getGuardianDashboard().catch(() => null),
      ]);
      setAlerts(alertList || []);
      if (gDash?.guarded_user) {
        setUserProfile(gDash.guarded_user);
      }
    } catch (err) {
      console.error('Error loading guardian alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleMarkRead = async (alertId) => {
    try {
      await api.markGuardianAlertRead(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, is_read: true } : a))
      );
    } catch (err) {
      console.error('Error marking alert as read:', err);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filter === 'HIGH') return a.severity === 'HIGH';
    if (filter === 'MEDIUM') return a.severity === 'MEDIUM';
    if (filter === 'LOW') return a.severity === 'LOW';
    if (filter === 'UNREAD') return !a.is_read;
    return true;
  });

  return (
    <GuardianLayout>
      <div className={styles.page}>
        <main className={styles.main}>
          <div className={styles.header}>
          <div>
            <span className={styles.sectionPill}>SECURITY LOGS</span>
            <h1 className={styles.title}>GUARDIAN SECURITY ALERTS</h1>
            <p className={styles.subtitle}>
              Review flagged cyber threats and risk assessments for {userProfile?.full_name || 'your protected user'}.
            </p>
          </div>

          {/* Filter tabs */}
          <div className={styles.filterRow}>
            {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'UNREAD'].map((f) => (
              <button
                key={f}
                className={`${styles.filterBtn} ${filter === f ? styles.filterBtnActive : ''}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* ── ALERTS LIST ── */}
        <section className={styles.alertsContainer}>
          {loading ? (
            <div className={styles.emptyState}>Loading security alerts from database…</div>
          ) : filteredAlerts.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>🛡️</span>
              <h3>No alerts match this filter</h3>
              <p>No incidents currently recorded under the selected category.</p>
            </div>
          ) : (
            <div className={styles.alertList}>
              {filteredAlerts.map((alert) => {
                const isHigh = alert.severity === 'HIGH';
                return (
                  <div
                    key={alert.id}
                    className={`${styles.alertCard} ${isHigh ? styles.alertCardHigh : ''}`}
                  >
                    <div className={styles.cardHeader}>
                      <div className={styles.threatTypeArea}>
                        <span className={styles.threatBadge}>{alert.threat_type || 'Security Incident'}</span>
                        <h3 className={styles.alertTitle}>{alert.title}</h3>
                      </div>
                      <div className={styles.badgesArea}>
                        <span className={isHigh ? styles.badgeHigh : styles.badgeMed}>
                          {alert.severity}
                        </span>
                        {!alert.is_read && (
                          <span className={styles.badgeUnread}>UNREAD</span>
                        )}
                      </div>
                    </div>

                    <div className={styles.actionBox}>
                      <span className={styles.actionLabel}>💡 RECOMMENDED GUARDIAN ACTION:</span>
                      <p className={styles.actionText}>{alert.recommended_action}</p>
                    </div>

                    <div className={styles.cardFooter}>
                      <span className={styles.timeText}>
                        Logged on {new Date(alert.created_at || alert.time).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>

                      {!alert.is_read && (
                        <button
                          className={styles.markReadBtn}
                          onClick={() => handleMarkRead(alert.id)}
                        >
                          Mark as Read ✓
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
        </main>
      </div>
    </GuardianLayout>
  );
}
