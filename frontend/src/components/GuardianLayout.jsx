import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import { guardianChatService } from '../services/guardianChatService';
import GuardianAIAssistantWidget from './GuardianAIAssistantWidget';
import styles from './GuardianLayout.module.css';

const NAV_SECTIONS = [
  {
    group: 'OVERVIEW',
    items: [
      { label: 'Dashboard', icon: '◈', path: '/guardian/dashboard' },
      { label: 'Private User Chat', icon: '💬', path: '/guardian/chat' },
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
  const [unreadChatCount, setUnreadChatCount] = useState(0);

  useEffect(() => {
    api.getGuardianDashboard().then(setGuardianData).catch(() => {});
    guardianChatService
      .getConversation()
      .then((conv) => {
        if (conv && typeof conv.unread_count === 'number') {
          setUnreadChatCount(conv.unread_count);
        }
      })
      .catch(() => {});
  }, [location.pathname]);

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
            {section.items.map((item) => {
              const active = isActive(item.path);
              const isChat = item.path === '/guardian/chat';
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`${styles.navItem} ${active ? styles.navItemActive : ''}`}
                >
                  <span className={styles.navIcon}>{item.icon}</span>
                  <span className={styles.navLabel}>{item.label}</span>
                  {isChat && unreadChatCount > 0 && (
                    <span className={styles.sidebarBadge}>{unreadChatCount}</span>
                  )}
                  {active && <span className={styles.activeBar} />}
                </Link>
              );
            })}
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
        {/* Desktop Top Header with Prominent Private User Chat button */}
        <header className={styles.topHeader}>
          <div className={styles.headerLeft}>
            <span className={styles.monitoringDot} />
            <span className={styles.monitoringLabel}>MONITORING:</span>
            <strong className={styles.monitoringName}>{protectedName}</strong>
          </div>

          <div className={styles.headerActions}>
            <Link
              to="/guardian/chat"
              className={styles.headerChatBtn}
              title="Private User Chat"
            >
              <span className={styles.chatIcon}>💬</span>
              <span className={styles.chatBtnLabel}>Private User Chat</span>
              {unreadChatCount > 0 && (
                <span className={styles.chatBadge} title={`${unreadChatCount} unread message(s)`}>
                  {unreadChatCount > 9 ? '9+' : unreadChatCount}
                </span>
              )}
            </Link>

            <Link to="/guardian/alerts" className={styles.headerAlertBtn} title="Security Alerts">
              <span>⚡</span>
              <span>Alerts</span>
            </Link>

            <Link to="/guardian/settings" className={styles.headerSettingsBtn} title="Guardian Settings">
              <span>⚙</span>
            </Link>
          </div>
        </header>

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
          <Link
            to="/guardian/chat"
            className={styles.mobileChatBtn}
            title="Private User Chat"
          >
            💬
            {unreadChatCount > 0 && (
              <span className={styles.mobileChatBadge}>{unreadChatCount}</span>
            )}
          </Link>
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
