import { useState, useEffect } from 'react';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './UserAlerts.module.css';

export default function UserAlerts() {
  const [userName, setUserName] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const [profile, alertData] = await Promise.all([
        api.getMe().catch(() => null),
        api.getSecurityAlerts().catch(() => []),
      ]);
      if (profile) setUserName(profile.full_name);
      if (alertData) setAlerts(alertData);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleMarkRead = async (id) => {
    try {
      await api.markAlertRead(id);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, is_read: true } : a))
      );
    } catch (err) {
      console.error('Error marking alert as read:', err);
    }
  };

  const getSeverityBadgeClass = (severity) => {
    if (severity === 'HIGH') return styles.severityHigh;
    if (severity === 'MEDIUM') return styles.severityMedium;
    return styles.severityLow;
  };

  return (
    <div className={styles.page}>
      <UserNav userName={userName} />

      <main className={styles.main}>
        <div className={styles.headerSection}>
          <h1 className={styles.pageTitle}>SECURITY ALERTS &amp; LOGS</h1>
          <p className={styles.pageSubtitle}>
            Review real-time incident alerts and security detections across your messages, links, and documents.
          </p>
        </div>

        <section className={styles.alertsCard}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '32px', color: '#737373' }}>
              Loading security alerts…
            </div>
          ) : alerts.length === 0 ? (
            <div className={styles.emptyState}>
              <div style={{ fontSize: '36px' }}>🛡️</div>
              <div className={styles.emptyTitle}>All Clear — No Security Alerts</div>
              <p style={{ fontSize: '13.5px', maxWidth: '400px' }}>
                Your scanned messages, links, and documents have not triggered any critical threats.
              </p>
            </div>
          ) : (
            <div className={styles.alertsList}>
              {alerts.map((alert) => (
                <div key={alert.id} className={styles.alertItem}>
                  <div className={styles.alertInfo}>
                    <div className={styles.alertTitleRow}>
                      {!alert.is_read && <span className={styles.unreadDot} title="Unread Alert" />}
                      <span className={styles.alertTitle}>{alert.title}</span>
                    </div>
                    <p className={styles.alertMessage}>{alert.message}</p>
                    <span className={styles.alertTime}>
                      {new Date(alert.created_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>

                  <div className={styles.alertMeta}>
                    <span className={`${styles.severityBadge} ${getSeverityBadgeClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    {!alert.is_read && (
                      <button
                        className={styles.markReadBtn}
                        onClick={() => handleMarkRead(alert.id)}
                      >
                        MARK READ
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
