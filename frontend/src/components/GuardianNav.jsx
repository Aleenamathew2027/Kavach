import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { clearAuth } from '../services/api';
import styles from './GuardianNav.module.css';

export default function GuardianNav({ guardianName = 'Guardian', protectedUserName = '' }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const navItems = [
    { label: 'Overview', path: '/guardian/dashboard' },
    { label: 'Protected User', path: '/guardian/protected-user' },
    { label: 'Security', path: '/guardian/security' },
    { label: 'Alerts', path: '/guardian/alerts' },
    { label: 'Activity', path: '/guardian/activity' },
    { label: 'Settings', path: '/guardian/settings' },
  ];

  return (
    <header className={styles.topNav}>
      <div className={styles.navContainer}>
        {/* Brand */}
        <div className={styles.logoArea}>
          <Link to="/guardian/dashboard" className={styles.logoText}>
            KAVACH
          </Link>
          <span className={styles.guardianTag}>GUARDIAN</span>
        </div>

        {/* Desktop Navigation */}
        <nav className={styles.navLinks} aria-label="Guardian Navigation">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`${styles.navLink} ${isActive ? styles.navLinkActive : ''}`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Right Info: Live Pulse & Logout */}
        <div className={styles.navRight}>
          <div className={styles.liveBadge}>
            <span className={styles.liveDot} />
            <span className={styles.liveText}>PROTECTION ACTIVE</span>
          </div>

          <div className={styles.guardianInfo}>
            <span className={styles.guardianName}>{guardianName}</span>
            {protectedUserName && (
              <span className={styles.protectingLabel}>Guarding: {protectedUserName}</span>
            )}
          </div>

          <button className={styles.logoutBtn} onClick={handleLogout}>
            Logout
          </button>

          {/* Mobile Menu Button */}
          <button
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle Mobile Guardian Navigation"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className={styles.mobileDrawer}>
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className={`${styles.mobileNavLink} ${isActive ? styles.mobileNavLinkActive : ''}`}
              >
                {item.label}
              </Link>
            );
          })}
          <div className={styles.mobileLogoutArea}>
            <button className={styles.mobileLogoutBtn} onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
