import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { clearAuth } from '../services/api';
import styles from './AdminNav.module.css';

export default function AdminNav({ adminEmail = 'admin@kavach.sec' }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const navItems = [
    { label: 'SOC Dashboard', path: '/admin/dashboard' },
    { label: 'Users', path: '/admin/users' },
    { label: 'Security Events', path: '/admin/security-events' },
    { label: 'Guardians', path: '/admin/guardians' },
    { label: 'Reports', path: '/admin/reports' },
    { label: 'System Activity', path: '/admin/activity' },
    { label: 'Settings', path: '/admin/settings' },
  ];

  return (
    <header className={styles.topNav}>
      <div className={styles.navContainer}>
        {/* Brand */}
        <div className={styles.logoArea}>
          <Link to="/admin/dashboard" className={styles.logoText}>
            KAVACH <span className={styles.socLabel}>SOC</span>
          </Link>
          <span className={styles.adminTag}>ADMIN</span>
        </div>

        {/* Desktop Navigation */}
        <nav className={styles.navLinks} aria-label="SOC Admin Navigation">
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

        {/* Right Area: System Status & Logout */}
        <div className={styles.navRight}>
          <div className={styles.statusBadge}>
            <span className={styles.statusPulse} />
            <span className={styles.statusText}>SOC ONLINE</span>
          </div>

          <div className={styles.adminInfo}>
            <span className={styles.adminEmail}>{adminEmail}</span>
            <span className={styles.secTier}>SYSTEM ADMINISTRATOR</span>
          </div>

          <button className={styles.logoutBtn} onClick={handleLogout}>
            Logout
          </button>

          {/* Mobile Menu Button */}
          <button
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle Mobile SOC Navigation"
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
