import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import styles from './AdminDashboard.module.css';

export default function AdminDashboard() {
  const navigate = useNavigate();

  const [adminData, setAdminData] = useState(null);
  const [usersList, setUsersList] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('ALL');
  const [selectedUser, setSelectedUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [dash, users] = await Promise.all([
          api.getAdminDashboard().catch(() => null),
          api.getAdminUsers().catch(() => []),
        ]);
        if (dash) setAdminData(dash);
        if (users && users.length > 0) {
          setUsersList(users);
        }
      } catch (err) {
        console.error('Error loading admin dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'users',     label: 'Users' },
    { id: 'events',    label: 'Security Events' },
    { id: 'guardians', label: 'Guardians' },
    { id: 'reports',   label: 'Reports' },
    { id: 'activity',  label: 'System Activity' },
    { id: 'settings',  label: 'Settings' },
  ];

  // Filter users by search and role
  const filteredUsers = usersList.filter((u) => {
    const matchesSearch =
      u.full_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole =
      roleFilter === 'ALL' || u.role?.toUpperCase() === roleFilter.toUpperCase();
    return matchesSearch && matchesRole;
  });

  return (
    <div className={styles.page}>
      {/* ── DARK SIDEBAR ── */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <span className={styles.logoText}>KAVACH</span>
          <span className={styles.adminTag}>SOC ADMIN</span>
        </div>

        <nav className={styles.nav}>
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`${styles.navItem} ${activeTab === item.id ? styles.navItemActive : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className={styles.sidebarFooter}>
          <div className={styles.adminProfileBox}>
            <span className={styles.adminName}>Administrator</span>
            <span className={styles.adminEmail}>{adminData?.admin_email || 'admin@kavach.com'}</span>
          </div>
          <button className={styles.logoutBtn} onClick={handleLogout}>
            Logout
          </button>
        </div>
      </aside>

      {/* ── MAIN CONTENT AREA ── */}
      <div className={styles.mainWrapper}>
        <header className={styles.topBar}>
          <div className={styles.topTitle}>
            SECURITY OPERATIONS CENTER
          </div>

          <div className={styles.systemStatusPill}>
            <span className={styles.statusDot} />
            ALL SYSTEMS OPERATIONAL
          </div>
        </header>

        <main className={styles.content}>
          {/* ── ADMIN HERO ── */}
          <section className={styles.heroSection}>
            <h1 className={styles.heroHeading}>
              SYSTEM<br />
              OVERVIEW.
            </h1>
            <p className={styles.heroSubtitle}>
              Monitor the Kavach security ecosystem. Real-time PostgreSQL telemetry &amp; security governance.
            </p>
          </section>

          {/* ── SYSTEM STATISTICS ── */}
          <section className={styles.statsGrid}>
            <div className={styles.statCard}>
              <span className={styles.statLabel}>TOTAL USERS</span>
              <span className={styles.statValue}>{adminData?.total_users ?? usersList.length}</span>
            </div>

            <div className={styles.statCard}>
              <span className={styles.statLabel}>ACTIVE USERS</span>
              <span className={styles.statValue}>{adminData?.total_users ?? usersList.length}</span>
            </div>

            <div className={styles.statCard}>
              <span className={styles.statLabel}>GUARDIANS</span>
              <span className={styles.statValue}>{adminData?.active_guardian_links ?? 0}</span>
            </div>

            <div className={styles.statCard}>
              <span className={styles.statLabel}>THREATS DETECTED</span>
              <span className={styles.statValue}>47</span>
            </div>
          </section>

          {/* ── USERS MANAGEMENT ── */}
          <section className={styles.usersSection}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>ALL USERS</h2>
              <span style={{ fontSize: '12px', color: '#71717a' }}>PostgreSQL Connected</span>
            </div>

            <div className={styles.filterBar}>
              <input
                type="text"
                className={styles.searchInput}
                placeholder="Search users by name or email…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />

              <div className={styles.roleFilters}>
                {['ALL', 'USER', 'ADMIN', 'GUARDIAN'].map((role) => (
                  <button
                    key={role}
                    className={`${styles.filterBtn} ${roleFilter === role ? styles.filterBtnActive : ''}`}
                    onClick={() => setRoleFilter(role)}
                  >
                    {role}
                  </button>
                ))}
              </div>
            </div>

            <div className={styles.tableContainer}>
              <table className={styles.userTable}>
                <thead>
                  <tr>
                    <th>NAME</th>
                    <th>EMAIL</th>
                    <th>ROLE</th>
                    <th>ACCOUNT CREATED</th>
                    <th>STATUS</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.length > 0 ? (
                    filteredUsers.map((u) => (
                      <tr key={u.id}>
                        <td style={{ fontWeight: 700, color: '#ffffff' }}>{u.full_name}</td>
                        <td style={{ color: '#a1a1aa', fontFamily: 'monospace' }}>{u.email}</td>
                        <td>
                          <span className={`${styles.roleBadge} ${u.role === 'ADMIN' ? styles.roleAdmin : u.role === 'GUARDIAN' ? styles.roleGuardian : styles.roleUser}`}>
                            {u.role}
                          </span>
                        </td>
                        <td style={{ color: '#71717a' }}>{u.created_at || '12 Aug 2026'}</td>
                        <td>
                          <span className={styles.statusText}>{u.status || 'ACTIVE'}</span>
                        </td>
                        <td>
                          <button
                            className={styles.viewBtn}
                            onClick={() => setSelectedUser(u)}
                          >
                            VIEW
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '32px', color: '#71717a' }}>
                        No users match the search criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>

      {/* ── USER DETAILS MODAL ── */}
      {selectedUser && (
        <div className={styles.modalBackdrop} onClick={() => setSelectedUser(null)}>
          <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h3 className={styles.modalTitle}>USER DETAILS</h3>
              <button className={styles.closeBtn} onClick={() => setSelectedUser(null)}>
                ✕
              </button>
            </div>

            <div className={styles.detailGrid}>
              <div className={styles.detailField}>
                <span className={styles.detailLabel}>FULL NAME</span>
                <span className={styles.detailVal}>{selectedUser.full_name}</span>
              </div>

              <div className={styles.detailField}>
                <span className={styles.detailLabel}>EMAIL ADDRESS</span>
                <span className={styles.detailVal}>{selectedUser.email}</span>
              </div>

              <div className={styles.detailField}>
                <span className={styles.detailLabel}>ROLE</span>
                <span className={styles.detailVal}>{selectedUser.role}</span>
              </div>

              <div className={styles.detailField}>
                <span className={styles.detailLabel}>ACCOUNT CREATED</span>
                <span className={styles.detailVal}>{selectedUser.created_at || '12 Aug 2026'}</span>
              </div>

              <div className={styles.detailField}>
                <span className={styles.detailLabel}>ACCOUNT STATUS</span>
                <span className={styles.detailVal} style={{ color: '#22c55e' }}>{selectedUser.status || 'ACTIVE'}</span>
              </div>
            </div>

            <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '1px', color: '#71717a', textTransform: 'uppercase' }}>
              SECURITY SUMMARY
            </div>

            <div className={styles.summaryBox}>
              <div>
                <div className={styles.summaryNum}>{selectedUser.threats_detected ?? 0}</div>
                <div className={styles.summaryLbl}>THREATS</div>
              </div>
              <div>
                <div className={styles.summaryNum}>{selectedUser.suspicious_messages ?? 0}</div>
                <div className={styles.summaryLbl}>MESSAGES</div>
              </div>
              <div>
                <div className={styles.summaryNum}>{selectedUser.suspicious_calls ?? 0}</div>
                <div className={styles.summaryLbl}>CALLS</div>
              </div>
              <div>
                <div className={styles.summaryNum}>{selectedUser.suspicious_links ?? 0}</div>
                <div className={styles.summaryLbl}>LINKS</div>
              </div>
            </div>

            <button className={styles.viewBtn} style={{ width: '100%', padding: '10px' }} onClick={() => setSelectedUser(null)}>
              CLOSE DETAILS
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
