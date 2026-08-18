import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { clearAuth } from '../services/api';
import styles from './UserNav.module.css';

export default function UserNav({ userName = 'Kavach User' }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const navItems = [
    { label: 'Overview', path: '/user/dashboard' },
    { label: 'Security', path: '/user/security' },
    { label: 'Message Scanner', path: '/user/messages' },
    { label: 'Link Checker', path: '/user/link-checker' },
    { label: 'Document Scanner', path: '/user/document-checker' },
    { label: 'Alerts', path: '/user/alerts' },
    { label: 'Profile', path: '/user/profile' },
  ];

  return (
    <header className={styles.topNav}>
      <div className={styles.navContainer}>
        {/* Brand */}
        <div className={styles.logoArea}>
          <Link to="/user/dashboard" className={styles.logoText}>KAVACH</Link>
          <span className={styles.roleBadge}>USER</span>
        </div>

        {/* Desktop Nav Links */}
        <nav className={styles.navLinks} aria-label="Main User Navigation">
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

        {/* User Profile Info & Logout */}
        <div className={styles.navRight}>
          <div className={styles.userInfo}>
            <span className={styles.userName}>{userName}</span>
            <span className={styles.userRoleTag}>USER</span>
          </div>
          <button className={styles.logoutBtn} onClick={handleLogout}>
            Logout
          </button>
          {/* Mobile Menu Button */}
          <button
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle Mobile Navigation"
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
              Logout ({userName})
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
