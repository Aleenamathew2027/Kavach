import { Link } from 'react-router-dom';
import styles from './Footer.module.css';

/**
 * Footer – landing page footer
 */
export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className={styles.footer} id="about">
      <div className={styles.container}>
        {/* Brand */}
        <div className={styles.brand}>
          <div className={styles.logo}>
            <span className={styles.logoIcon}>⚡</span>
            <span className={styles.logoText}>KAVACH</span>
          </div>
          <p className={styles.tagline}>
            AI-powered digital safety platform
          </p>
          <p className={styles.description}>
            Protecting users from phishing, scam messages, deepfake voices,
            and digital fraud using advanced AI analysis.
          </p>
        </div>

        {/* Links */}
        <div className={styles.links}>
          <div className={styles.linkGroup}>
            <h3 className={styles.linkGroupTitle}>Platform</h3>
            <ul className={styles.linkList}>
              <li><Link to="/register">Get Started</Link></li>
              <li><Link to="/login">Login</Link></li>
              <li><Link to="/dashboard">Dashboard</Link></li>
            </ul>
          </div>

          <div className={styles.linkGroup}>
            <h3 className={styles.linkGroupTitle}>Features</h3>
            <ul className={styles.linkList}>
              <li><span>Scam Detection</span></li>
              <li><span>Voice Protection</span></li>
              <li><span>Phishing Guard</span></li>
              <li><span>AI Risk Analysis</span></li>
            </ul>
          </div>

          <div className={styles.linkGroup}>
            <h3 className={styles.linkGroupTitle}>About</h3>
            <ul className={styles.linkList}>
              <li><span>Final Year Project</span></li>
              <li><span>AI Security Research</span></li>
              <li><span>Documentation</span></li>
            </ul>
          </div>
        </div>
      </div>

      <div className={styles.bottom}>
        <div className={styles.bottomInner}>
          <p className={styles.copyright}>
            © {currentYear} KAVACH. Built as an AI Security Research Project.
          </p>
          <div className={styles.badges}>
            <span className={styles.badge}>🛡️ AI-Powered</span>
            <span className={styles.badge}>🔒 Privacy First</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
