import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import styles from './Navbar.module.css';

/**
 * Navbar – landing page navigation bar
 */
export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const navigate = useNavigate();

  const toggleMenu = () => setMenuOpen((prev) => !prev);

  const scrollTo = (id) => {
    setMenuOpen(false);
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <nav className={styles.navbar} role="navigation" aria-label="Main navigation">
      <div className={styles.container}>
        {/* Logo */}
        <Link to="/" className={styles.logo} aria-label="KAVACH home">
          <span className={styles.logoIcon}>⚡</span>
          <span className={styles.logoText}>KAVACH</span>
        </Link>

        {/* Desktop nav links */}
        <ul className={styles.navLinks} role="list">
          <li><button className={styles.navLink} onClick={() => scrollTo('hero')}>Home</button></li>
          <li><button className={styles.navLink} onClick={() => scrollTo('features')}>Features</button></li>
          <li><button className={styles.navLink} onClick={() => scrollTo('how-it-works')}>How It Works</button></li>
          <li><button className={styles.navLink} onClick={() => scrollTo('about')}>About</button></li>
        </ul>

        {/* Auth buttons */}
        <div className={styles.authButtons}>
          <button
            className={styles.btnOutline}
            onClick={() => navigate('/login')}
            aria-label="Log in to KAVACH"
          >
            Login
          </button>
          <button
            className={styles.btnPrimary}
            onClick={() => navigate('/register')}
            aria-label="Get started with KAVACH"
          >
            Get Started
          </button>
        </div>

        {/* Hamburger */}
        <button
          className={`${styles.hamburger} ${menuOpen ? styles.open : ''}`}
          onClick={toggleMenu}
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={menuOpen}
        >
          <span /><span /><span />
        </button>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div className={styles.mobileMenu} role="menu">
          <button className={styles.mobileLink} onClick={() => scrollTo('hero')}>Home</button>
          <button className={styles.mobileLink} onClick={() => scrollTo('features')}>Features</button>
          <button className={styles.mobileLink} onClick={() => scrollTo('how-it-works')}>How It Works</button>
          <button className={styles.mobileLink} onClick={() => scrollTo('about')}>About</button>
          <div className={styles.mobileDivider} />
          <button className={styles.mobileLink} onClick={() => { setMenuOpen(false); navigate('/login'); }}>Login</button>
          <button className={`${styles.mobileLink} ${styles.mobilePrimary}`} onClick={() => { setMenuOpen(false); navigate('/register'); }}>
            Get Started
          </button>
        </div>
      )}
    </nav>
  );
}
