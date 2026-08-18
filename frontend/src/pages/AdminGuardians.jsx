import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminGuardians.module.css';

export default function AdminGuardians() {
  const [guardians, setGuardians] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function loadGuardians() {
      setLoading(true);
      try {
        const data = await api.getAdminGuardians();
        setGuardians(data || []);
      } catch (err) {
        console.error('Error loading guardian links:', err);
      } finally {
        setLoading(false);
      }
    }
    loadGuardians();
  }, []);

  const filtered = guardians.filter((g) => {
    return (
      (g.user_name || '').toLowerCase().includes(search.toLowerCase()) ||
      (g.user_email || '').toLowerCase().includes(search.toLowerCase()) ||
      (g.status || '').toLowerCase().includes(search.toLowerCase())
    );
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
            <span className={styles.sectionPill}>TRUST & ACCESS DELEGATION</span>
            <h1 className={styles.title}>GUARDIAN LINKAGES</h1>
            <p className={styles.subtitle}>
              Active and historical family guardian access authorizations for protected users.
            </p>
          </div>

          <input
            type="text"
            className={styles.searchInput}
            placeholder="Search protected user or status…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* ── GUARDIANS TABLE ── */}
        <section className={styles.tablePanel}>
          {loading ? (
            <div className={styles.emptyState}>Loading guardian authorizations…</div>
          ) : filtered.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>🛡️</span>
              <h3>No guardian links found</h3>
              <p>When users generate 6-digit access passes, authorized links will be indexed here.</p>
            </div>
          ) : (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>LINK ID</th>
                    <th>PROTECTED USER</th>
                    <th>RELATIONSHIP</th>
                    <th>STATUS</th>
                    <th>CREATED AT</th>
                    <th>EXPIRES AT</th>
                    <th>ACCESS PRIVILEGES</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((g) => {
                    const isActive = g.status === 'ACTIVE';
                    const isRevoked = g.status === 'REVOKED';
                    return (
                      <tr key={g.id}>
                        <td className={styles.monoCell}>GDN-{g.id}</td>
                        <td>
                          <div className={styles.userCell}>
                            <span className={styles.userName}>{g.user_name}</span>
                            <span className={styles.userEmail}>{g.user_email}</span>
                          </div>
                        </td>
                        <td className={styles.relationCell}>{g.relationship}</td>
                        <td>
                          <span
                            className={
                              isActive
                                ? styles.statusActive
                                : isRevoked
                                ? styles.statusRevoked
                                : styles.statusExpired
                            }
                          >
                            {g.status}
                          </span>
                        </td>
                        <td className={styles.timeCell}>
                          {g.created_at
                            ? new Date(g.created_at).toLocaleString([], {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                              })
                            : '—'}
                        </td>
                        <td className={styles.timeCell}>
                          {g.expires_at
                            ? new Date(g.expires_at).toLocaleString([], {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                              })
                            : '—'}
                        </td>
                        <td>
                          <span className={styles.privilegeTag}>High-Level Telemetry Only</span>
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
