import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import styles from './DashboardNav.module.css';

const navItems = [
  { id: 'dashboard',       label: 'Dashboard',       icon: '🏠' },
  { id: 'threat-analysis', label: 'Threat Analysis',  icon: '🔍' },
  { id: 'messages',        label: 'Messages',         icon: '💬' },
  { id: 'voice-analysis',  label: 'Voice Analysis',   icon: '🎙️' },
  { id: 'payments',        label: 'Payments',         icon: '💳' },
  { id: 'documents',       label: 'Documents',        icon: '📄' },
  { id: 'profile',         label: 'Profile',          icon: '👤' },
];

/**
 * DashboardNav – top navigation bar for the dashboard
 */
export default function DashboardNav() {
  const navigate = useNavigate();
  const [activeItem, setActiveItem] = useState('dashboard');
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('kavach_logged_in');
    navigate('/login');
  };

  return (
    <header className={styles.header}>
      <div className={styles.inner}>
        {/* Logo */}
        <div className={styles.logo}>
          <span className={styles.logoIcon}>⚡</span>
          <span className={styles.logoText}>KAVACH</span>
        </div>

        {/* Nav links (desktop) */}
        <nav className={styles.nav} aria-label="Dashboard navigation">
          <ul className={styles.navList} role="list">
            {navItems.map((item) => (
              <li key={item.id}>
                <button
                  className={`${styles.navItem} ${activeItem === item.id ? styles.active : ''}`}
                  onClick={() => setActiveItem(item.id)}
                  aria-current={activeItem === item.id ? 'page' : undefined}
                  id={`nav-${item.id}`}
                >
                  <span className={styles.navIcon} aria-hidden="true">{item.icon}</span>
                  <span className={styles.navLabel}>{item.label}</span>
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* Right side */}
        <div className={styles.right}>
          <div className={styles.statusBadge} title="Security status: Protected">
            <span className={styles.statusDot} />
            Protected
          </div>
          <button
            className={styles.logoutBtn}
            onClick={handleLogout}
            id="logout-button"
            aria-label="Logout from KAVACH"
          >
            <span aria-hidden="true">🚪</span> Logout
          </button>
          {/* Mobile hamburger */}
          <button
            className={styles.hamburger}
            onClick={() => setMobileOpen((v) => !v)}
            aria-label="Toggle navigation"
          >
            ☰
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {mobileOpen && (
        <nav className={styles.mobileNav} aria-label="Mobile dashboard navigation">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`${styles.mobileNavItem} ${activeItem === item.id ? styles.mobileActive : ''}`}
              onClick={() => { setActiveItem(item.id); setMobileOpen(false); }}
            >
              {item.icon} {item.label}
            </button>
          ))}
          <button className={styles.mobileLogout} onClick={handleLogout}>
            🚪 Logout
          </button>
        </nav>
      )}
    </header>
  );
}
