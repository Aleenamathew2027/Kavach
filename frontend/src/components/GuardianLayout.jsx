import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import GuardianAIAssistantWidget from './GuardianAIAssistantWidget';
import styles from './GuardianLayout.module.css';

const NAV_SECTIONS = [
  {
    group: 'OVERVIEW',
    items: [
      { label: 'Dashboard', icon: '◈', path: '/guardian/dashboard' },
    ],
  },
  {
    group: 'MONITORING',
    items: [
      { label: 'Security Alerts', icon: '⚡', path: '/guardian/alerts' },
      { label: 'Security Activity', icon: '📋', path: '/guardian/activity' },
      { label: 'Incident Reports', icon: '📄', path: '/guardian/reports' },
    ],
  },
  {
    group: 'PROTECTION',
    items: [
      { label: 'Security Modules', icon: '🛡', path: '/guardian/security' },
    ],
  },
  {
    group: 'ACCOUNT',
    items: [
      { label: 'Protected User', icon: '👤', path: '/guardian/protected-user' },
      { label: 'Settings', icon: '⚙', path: '/guardian/settings' },
    ],
  },
];

/**
 * GuardianLayout — shared sidebar layout for all Guardian pages.
 * Replaces the old horizontal GuardianNav.
 * Loads guardian data internally to display protected user name in sidebar.
 */
export default function GuardianLayout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [guardianData, setGuardianData] = useState(null);

  useEffect(() => {
    api.getGuardianDashboard().then(setGuardianData).catch(() => {});
  }, []);

  useEffect(() => {
    // Close mobile sidebar on navigation
    setMobileOpen(false);
  }, [location.pathname]);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const protectedName = guardianData?.guarded_user?.full_name || 'Protected User';
  const isActive = (path) => location.pathname === path;

  const sidebarContent = (
    <aside className={styles.sidebar}>
      {/* Brand */}
      <div className={styles.brand}>
        <span className={styles.brandIcon}>🛡</span>
        <div>
          <div className={styles.brandName}>KAVACH</div>
          <div className={styles.brandRole}>GUARDIAN CONSOLE</div>
        </div>
      </div>

      {/* Nav Sections */}
      <nav className={styles.nav}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.group} className={styles.navGroup}>
            <span className={styles.navGroupLabel}>{section.group}</span>
            {section.items.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`${styles.navItem} ${isActive(item.path) ? styles.navItemActive : ''}`}
              >
                <span className={styles.navIcon}>{item.icon}</span>
                <span className={styles.navLabel}>{item.label}</span>
                {isActive(item.path) && <span className={styles.activeBar} />}
              </Link>
            ))}
          </div>
        ))}
      </nav>

      {/* Sidebar Footer */}
      <div className={styles.sidebarFooter}>
        <div className={styles.protectedUserBadge}>
          <span className={styles.protectedUserIcon}>👤</span>
          <div className={styles.protectedUserInfo}>
            <span className={styles.protectedUserLabel}>MONITORING</span>
            <span className={styles.protectedUserName} title={protectedName}>
              {protectedName}
            </span>
          </div>
          <span className={styles.activeDot} title="Protection Active" />
        </div>

        <button type="button" className={styles.logoutBtn} onClick={handleLogout}>
          <span>⏻</span>
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );

  return (
    <div className={styles.layout}>
      {/* Desktop sidebar */}
      {sidebarContent}

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className={styles.mobileOverlay}
          onClick={() => setMobileOpen(false)}
        />
      )}
      <div className={`${styles.mobileSidebar} ${mobileOpen ? styles.mobileSidebarOpen : ''}`}>
        {sidebarContent}
      </div>

      {/* Main area */}
      <div className={styles.mainWrapper}>
        {/* Mobile top bar */}
        <div className={styles.mobileTopBar}>
          <button
            className={styles.hamburger}
            onClick={() => setMobileOpen(true)}
            aria-label="Open menu"
          >
            ☰
          </button>
          <div className={styles.mobileBrand}>
            <span>🛡</span> KAVACH GUARDIAN
          </div>
        </div>

        <main className={styles.main}>
          {children}
        </main>
      </div>

      {/* Floating AI Assistant Widget — visible on all Guardian pages */}
      <GuardianAIAssistantWidget />
    </div>
  );
}
