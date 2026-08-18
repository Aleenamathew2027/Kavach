import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminSecurityEvents.module.css';

export default function AdminSecurityEvents() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterType, setFilterType] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  useEffect(() => {
    async function loadEvents() {
      setLoading(true);
      try {
        const data = await api.getAdminSecurityEvents();
        setEvents(data || []);
      } catch (err) {
        console.error('Error loading security events:', err);
      } finally {
        setLoading(false);
      }
    }
    loadEvents();
  }, []);

  const filteredEvents = events.filter((e) => {
    const matchSearch =
      (e.user_name || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.user_email || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.input_reference || '').toLowerCase().includes(search.toLowerCase());

    const matchSeverity =
      filterSeverity === 'ALL' ||
      (filterSeverity === 'HIGH' && e.risk_level === 'HIGH RISK') ||
      (filterSeverity === 'SUSPICIOUS' && e.risk_level === 'SUSPICIOUS') ||
      (filterSeverity === 'SAFE' && e.risk_level === 'SAFE');

    const matchType =
      filterType === 'ALL' || (e.scan_type || '').toLowerCase() === filterType.toLowerCase();

    return matchSearch && matchSeverity && matchType;
  });

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
            <span className={styles.sectionPill}>INCIDENT MANAGEMENT</span>
            <h1 className={styles.title}>SECURITY EVENTS & SCANS</h1>
            <p className={styles.subtitle}>
              Live telemetry log of all safety scans executed across KAVACH.
            </p>
          </div>

          <div className={styles.controlsRow}>
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search user or domain…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />

            <div className={styles.filterGroup}>
              {['ALL', 'HIGH', 'SUSPICIOUS', 'SAFE'].map((s) => (
                <button
                  key={s}
                  className={`${styles.filterBtn} ${filterSeverity === s ? styles.filterBtnActive : ''}`}
                  onClick={() => setFilterSeverity(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ── EVENTS TABLE ── */}
        <section className={styles.tablePanel}>
          {loading ? (
            <div className={styles.emptyState}>Loading security telemetry from PostgreSQL…</div>
          ) : filteredEvents.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>🛡️</span>
              <h3>No security events found</h3>
              <p>No logged scans matched your search or filters.</p>
            </div>
          ) : (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>SCAN ID</th>
                    <th>USER</th>
                    <th>CHANNEL</th>
                    <th>TARGET / PREVIEW</th>
                    <th>RISK LEVEL</th>
                    <th>RISK SCORE</th>
                    <th>TIMESTAMP</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((evt) => {
                    const isHigh = evt.risk_level === 'HIGH RISK';
                    const isSuspicious = evt.risk_level === 'SUSPICIOUS';
                    return (
                      <tr key={evt.id}>
                        <td className={styles.monoCell}>#{evt.id}</td>
                        <td>
                          <div className={styles.userCell}>
                            <span className={styles.userName}>{evt.user_name}</span>
                            <span className={styles.userEmail}>{evt.user_email}</span>
                          </div>
                        </td>
                        <td>
                          <span className={styles.typeTag}>{evt.scan_type.toUpperCase()}</span>
                        </td>
                        <td className={styles.previewCell}>{evt.input_reference}</td>
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
                            {evt.risk_level}
                          </span>
                        </td>
                        <td className={styles.scoreCell}>{evt.risk_score}/100</td>
                        <td className={styles.timeCell}>
                          {evt.created_at
                            ? new Date(evt.created_at).toLocaleString([], {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                              })
                            : 'Just now'}
                        </td>
                        <td>
                          <button
                            className={styles.viewBtn}
                            onClick={() => setSelectedEvent(evt)}
                          >
                            Inspect
                          </button>
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

      {/* ── EVENT INSPECTION MODAL ── */}
      {selectedEvent && (
        <div className={styles.modalOverlay} onClick={() => setSelectedEvent(null)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>SCAN INCIDENT TELEMETRY</h2>
              <button className={styles.closeBtn} onClick={() => setSelectedEvent(null)}>✕</button>
            </div>

            <div className={styles.detailsGrid}>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Scan ID</span>
                <span className={styles.detailVal}>#{selectedEvent.id}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>User</span>
                <span className={styles.detailVal}>{selectedEvent.user_name} ({selectedEvent.user_email})</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Channel</span>
                <span className={styles.detailVal}>{selectedEvent.scan_type.toUpperCase()}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Risk Level</span>
                <span className={selectedEvent.risk_level === 'HIGH RISK' ? styles.badgeHigh : styles.badgeSafe}>
                  {selectedEvent.risk_level} ({selectedEvent.risk_score}/100)
                </span>
              </div>
              <div className={styles.detailItemFull}>
                <span className={styles.detailLabel}>Input Reference / URL</span>
                <span className={styles.detailVal}>{selectedEvent.input_reference}</span>
              </div>
              <div className={styles.detailItemFull}>
                <span className={styles.detailLabel}>Summary / Verdict</span>
                <span className={styles.detailVal}>{selectedEvent.summary}</span>
              </div>
              {selectedEvent.detected_indicators && selectedEvent.detected_indicators.length > 0 && (
                <div className={styles.detailItemFull}>
                  <span className={styles.detailLabel}>Detected Rule Indicators</span>
                  <div className={styles.indicatorsList}>
                    {selectedEvent.detected_indicators.map((ind, i) => (
                      <span key={i} className={styles.indTag}>{ind}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className={styles.modalFooter}>
              <button className={styles.modalCloseBtn} onClick={() => setSelectedEvent(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
