import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import AdminNav from '../components/AdminNav';
import styles from './AdminUsers.module.css';

export default function AdminUsers() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('ALL');
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    async function loadUsers() {
      setLoading(true);
      try {
        const data = await api.getAdminUsers();
        setUsers(data || []);
      } catch (err) {
        console.error('Error loading users:', err);
      } finally {
        setLoading(false);
      }
    }
    loadUsers();
  }, []);

  const filteredUsers = users.filter((u) => {
    const matchSearch =
      (u.full_name || '').toLowerCase().includes(search.toLowerCase()) ||
      (u.email || '').toLowerCase().includes(search.toLowerCase());
    const matchRole = roleFilter === 'ALL' || u.role === roleFilter;
    return matchSearch && matchRole;
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
            <span className={styles.sectionPill}>IDENTITY & ACCESS REGISTRY</span>
            <h1 className={styles.title}>USER MANAGEMENT</h1>
            <p className={styles.subtitle}>
              PostgreSQL database user accounts and real-time security scan counts.
            </p>
          </div>

          <div className={styles.controlsRow}>
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search by name or email…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />

            <div className={styles.roleTabs}>
              {['ALL', 'USER', 'ADMIN', 'GUARDIAN'].map((r) => (
                <button
                  key={r}
                  className={`${styles.roleTab} ${roleFilter === r ? styles.roleTabActive : ''}`}
                  onClick={() => setRoleFilter(r)}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ── USERS TABLE ── */}
        <section className={styles.tablePanel}>
          {loading ? (
            <div className={styles.emptyState}>Loading accounts from PostgreSQL…</div>
          ) : filteredUsers.length === 0 ? (
            <div className={styles.emptyState}>
              <span style={{ fontSize: '32px' }}>👥</span>
              <h3>No users found</h3>
              <p>No account matched your search or role filter.</p>
            </div>
          ) : (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>USER ID</th>
                    <th>FULL NAME</th>
                    <th>EMAIL ADDRESS</th>
                    <th>ROLE</th>
                    <th>STATUS</th>
                    <th>TOTAL SCANS</th>
                    <th>THREATS</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((u) => (
                    <tr key={u.id}>
                      <td className={styles.monoCell}>USR-{u.id}</td>
                      <td className={styles.nameCell}>{u.full_name}</td>
                      <td className={styles.emailCell}>{u.email}</td>
                      <td>
                        <span className={u.role === 'ADMIN' ? styles.roleAdmin : styles.roleUser}>
                          {u.role}
                        </span>
                      </td>
                      <td>
                        <span className={styles.statusActive}>ACTIVE</span>
                      </td>
                      <td className={styles.numCell}>{u.total_scans ?? 0}</td>
                      <td className={styles.numCell} style={u.threats_detected > 0 ? { color: '#ef4444', fontWeight: 800 } : {}}>
                        {u.threats_detected ?? 0}
                      </td>
                      <td>
                        <button
                          className={styles.viewBtn}
                          onClick={() => setSelectedUser(u)}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>

      {/* ── USER DETAILS MODAL ── */}
      {selectedUser && (
        <div className={styles.modalOverlay} onClick={() => setSelectedUser(null)}>
          <div className={styles.modalBox} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h2 className={styles.modalTitle}>USER TELEMETRY DETAILS</h2>
              <button className={styles.closeBtn} onClick={() => setSelectedUser(null)}>✕</button>
            </div>

            <div className={styles.detailsGrid}>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>User ID</span>
                <span className={styles.detailVal}>USR-{selectedUser.id}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Full Name</span>
                <span className={styles.detailVal}>{selectedUser.full_name}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Email Address</span>
                <span className={styles.detailVal}>{selectedUser.email}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Account Role</span>
                <span className={styles.detailVal}>{selectedUser.role}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Total Security Scans</span>
                <span className={styles.detailVal}>{selectedUser.total_scans ?? 0}</span>
              </div>
              <div className={styles.detailItem}>
                <span className={styles.detailLabel}>Threats Intercepted</span>
                <span className={styles.detailVal}>{selectedUser.threats_detected ?? 0}</span>
              </div>
            </div>

            <div className={styles.modalFooter}>
              <button className={styles.modalCloseBtn} onClick={() => setSelectedUser(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
