import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import AIAssistantWidget from './AIAssistantWidget';
import styles from './UserLayout.module.css';

export default function UserLayout({
  children,
  eyebrow,
  title,
  subtitle,
  headerAction,
  hidePageHeader = false,
}) {
  const location = useLocation();
  const navigate = useNavigate();

  const [userProfile, setUserProfile] = useState(null);
  const [unreadAlertsCount, setUnreadAlertsCount] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Security group is open if on any security route or toggled by user
  const isSecurityRoute = [
    '/user/security',
    '/user/messages',
    '/user/link-checker',
    '/user/document-checker',
    '/user/qr-scanner',
  ].some((r) => location.pathname.startsWith(r));

  const [securityMenuOpen, setSecurityMenuOpen] = useState(isSecurityRoute);

  useEffect(() => {
    if (isSecurityRoute) {
      setSecurityMenuOpen(true);
    }
  }, [location.pathname, isSecurityRoute]);

  useEffect(() => {
    async function loadHeaderData() {
      try {
        const [profile, alerts] = await Promise.all([
          api.getMe().catch(() => null),
          api.getSecurityAlerts().catch(() => []),
        ]);
        if (profile) setUserProfile(profile);
        if (Array.isArray(alerts)) {
          const unread = alerts.filter((a) => !a.is_read).length;
          setUnreadAlertsCount(unread);
        }
      } catch (err) {
        console.error('Failed to load user layout data:', err);
      }
    }
    loadHeaderData();
  }, [location.pathname]);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const getInitials = (name) => {
    if (!name) return 'U';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    return parts[0][0].toUpperCase();
  };

  const userName = userProfile?.full_name || 'Kavach Citizen';

  return (
    <div className={styles.appShell}>
      {/* ── DESKTOP PERSISTENT SIDEBAR NAVIGATION ── */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <Link to="/user/dashboard" className={styles.brandLogo}>
            KAVACH<span className={styles.brandDot}>.</span>
          </Link>
          <span className={styles.brandTagline}>AI CYBER GUARDIAN</span>
        </div>

        {/* User Card in Sidebar */}
        <div className={styles.userBadgeCard}>
          <div className={styles.userAvatarMini}>{getInitials(userName)}</div>
          <div className={styles.userBadgeInfo}>
            <span className={styles.userBadgeName}>{userName}</span>
            <span className={styles.userBadgeRole}>SECURE CITIZEN</span>
          </div>
        </div>

        {/* Sidebar Navigation Items */}
        <nav className={styles.sidebarNav} aria-label="Main User Navigation">
          {/* Section: Overview */}
          <span className={styles.navSectionLabel}>OVERVIEW</span>
          <Link
            to="/user/dashboard"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/dashboard' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>❖</span>
            <span>Dashboard</span>
          </Link>

          {/* Section: Security (Expandable Group) */}
          <span className={styles.navSectionLabel}>SECURITY</span>
          <button
            type="button"
            className={`${styles.groupHeader} ${
              isSecurityRoute ? styles.groupHeaderActive : ''
            }`}
            onClick={() => setSecurityMenuOpen(!securityMenuOpen)}
          >
            <div className={styles.groupLeft}>
              <span className={styles.navIcon}>🛡️</span>
              <span>Detection Suite</span>
            </div>
            <span
              className={`${styles.groupChevron} ${
                securityMenuOpen ? styles.groupChevronOpen : ''
              }`}
            >
              ▶
            </span>
          </button>

          {securityMenuOpen && (
            <div className={styles.subMenuList}>
              <Link
                to="/user/security"
                className={`${styles.subMenuItem} ${
                  location.pathname === '/user/security' ? styles.subMenuItemActive : ''
                }`}
              >
                <span>• Security Center</span>
              </Link>
              <Link
                to="/user/messages"
                className={`${styles.subMenuItem} ${
                  location.pathname === '/user/messages' ? styles.subMenuItemActive : ''
                }`}
              >
                <span>• Message Scanner</span>
              </Link>
              <Link
                to="/user/link-checker"
                className={`${styles.subMenuItem} ${
                  location.pathname === '/user/link-checker' ? styles.subMenuItemActive : ''
                }`}
              >
                <span>• Link Checker</span>
              </Link>
              <Link
                to="/user/document-checker"
                className={`${styles.subMenuItem} ${
                  location.pathname === '/user/document-checker' ? styles.subMenuItemActive : ''
                }`}
              >
                <span>• Document Scanner</span>
              </Link>
              <Link
                to="/user/qr-scanner"
                className={`${styles.subMenuItem} ${
                  location.pathname === '/user/qr-scanner' ? styles.subMenuItemActive : ''
                }`}
              >
                <span>• QR Scanner</span>
              </Link>
            </div>
          )}

          {/* Section: Monitoring */}
          <span className={styles.navSectionLabel}>MONITORING</span>
          <Link
            to="/user/alerts"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/alerts' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>🔔</span>
            <span>Alerts</span>
          </Link>
          <Link
            to="/user/reports"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/reports' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>📄</span>
            <span>Incident Reports</span>
          </Link>

          {/* Section: Protection */}
          <span className={styles.navSectionLabel}>PROTECTION</span>
          <Link
            to="/user/assistant"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/assistant' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>✦</span>
            <span>AI Assistant</span>
          </Link>
          <Link
            to="/user/guardian"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/guardian' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>👥</span>
            <span>Guardian Access</span>
          </Link>

          {/* Section: Account */}
          <span className={styles.navSectionLabel}>ACCOUNT</span>
          <Link
            to="/user/profile"
            className={`${styles.sidebarLink} ${
              location.pathname === '/user/profile' ? styles.sidebarLinkActive : ''
            }`}
          >
            <span className={styles.navIcon}>⚙</span>
            <span>Profile &amp; Settings</span>
          </Link>
        </nav>

        {/* Sidebar Footer */}
        <div className={styles.sidebarFooter}>
          <div className={styles.systemStatusPill}>
            <span className={styles.statusLiveDot} />
            <span>Shield Active • 24/7</span>
          </div>
          <button
            type="button"
            className={styles.sidebarLogoutBtn}
            onClick={handleLogout}
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── MOBILE TOP BAR (< 1080px) ── */}
      <div className={styles.mobileTopBar}>
        <Link to="/user/dashboard" className={styles.brandLogo} style={{ fontSize: '18px' }}>
          KAVACH<span className={styles.brandDot}>.</span>
        </Link>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Link to="/user/alerts" className={styles.headerAlertBtn} style={{ padding: '6px 10px' }}>
            🔔
            {unreadAlertsCount > 0 && (
              <span className={styles.alertCountBadge}>{unreadAlertsCount}</span>
            )}
          </Link>
          <button
            type="button"
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>

      {/* ── MOBILE DRAWER OVERLAY ── */}
      <div
        className={`${styles.mobileDrawerOverlay} ${
          mobileMenuOpen ? styles.mobileDrawerOpen : ''
        }`}
      >
        <Link
          to="/user/dashboard"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/dashboard' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Dashboard
        </Link>
        <Link
          to="/user/security"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/security' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Security Center
        </Link>
        <Link
          to="/user/messages"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/messages' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Message Scanner
        </Link>
        <Link
          to="/user/link-checker"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/link-checker' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Link Checker
        </Link>
        <Link
          to="/user/document-checker"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/document-checker' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Document Scanner
        </Link>
        <Link
          to="/user/qr-scanner"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/qr-scanner' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          QR Scanner
        </Link>
        <Link
          to="/user/alerts"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/alerts' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Alerts {unreadAlertsCount > 0 ? `(${unreadAlertsCount})` : ''}
        </Link>
        <Link
          to="/user/reports"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/reports' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Incident Reports
        </Link>
        <Link
          to="/user/guardian"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/guardian' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Guardian Access
        </Link>
        <Link
          to="/user/assistant"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/assistant' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          AI Assistant
        </Link>
        <Link
          to="/user/profile"
          className={`${styles.mobileDrawerLink} ${
            location.pathname === '/user/profile' ? styles.mobileDrawerLinkActive : ''
          }`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Profile &amp; Settings
        </Link>
        <button
          type="button"
          className={styles.sidebarLogoutBtn}
          style={{ marginTop: '16px' }}
          onClick={handleLogout}
        >
          Sign Out ({userName})
        </button>
      </div>

      {/* ── MAIN CONTENT CANVAS ── */}
      <div className={styles.mainCanvas}>
        {/* Top Header Surface */}
        <header className={styles.topHeader}>
          <div className={styles.headerGreeting}>
            <h1 className={styles.greetingTitle}>
              Welcome, {userName}
            </h1>
            <p className={styles.greetingSub}>
              System Shield Active • Continuous Threat Telemetry &amp; Detection
            </p>
          </div>

          <div className={styles.headerActions}>
            <Link to="/user/alerts" className={styles.headerAlertBtn} title="View Alerts">
              <span>🔔</span>
              <span>Alerts</span>
              {unreadAlertsCount > 0 && (
                <span className={styles.alertCountBadge}>{unreadAlertsCount}</span>
              )}
            </Link>

            <Link
              to="/user/guardian"
              className={styles.headerAiTriggerBtn}
              title="Manage Guardian Access"
            >
              + Guardian Code
            </Link>

            <Link
              to="/user/profile"
              className={styles.userAvatarMini}
              style={{ width: '36px', height: '36px', textDecoration: 'none' }}
              title="Profile Settings"
            >
              {getInitials(userName)}
            </Link>
          </div>
        </header>

        {/* Page Content Canvas */}
        <main className={styles.contentArea}>
          {!hidePageHeader && title && (
            <div className={styles.pageHeader}>
              <div className={styles.pageHeaderLeft}>
                {eyebrow && <span className={styles.pageEyebrow}>{eyebrow}</span>}
                <h2 className={styles.pageTitle}>{title}</h2>
                {subtitle && <p className={styles.pageSubtitle}>{subtitle}</p>}
              </div>
              {headerAction && <div>{headerAction}</div>}
            </div>
          )}

          {children}
        </main>
      </div>

      {/* ── PERSISTENT FLOATING AI ASSISTANT WIDGET (ALL USER PAGES) ── */}
      <AIAssistantWidget />
    </div>
  );
}
