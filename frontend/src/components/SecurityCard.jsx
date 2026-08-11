import styles from './SecurityCard.module.css';

/**
 * SecurityCard – stat/overview card for the Dashboard
 *
 * @param {string} icon     - Emoji icon
 * @param {string} label    - Card label
 * @param {string} value    - Main displayed value
 * @param {string} status   - Optional status badge text
 * @param {string} variant  - Color variant: 'blue' | 'green' | 'purple' | 'orange'
 */
export default function SecurityCard({ icon, label, value, status, variant = 'blue' }) {
  return (
    <div className={`${styles.card} ${styles[variant]}`} role="region" aria-label={label}>
      <div className={styles.header}>
        <span className={styles.label}>{label}</span>
        <span className={styles.icon} role="img" aria-hidden="true">{icon}</span>
      </div>
      <div className={styles.value}>{value}</div>
      {status && (
        <div className={styles.statusBadge}>
          <span className={styles.dot} />
          {status}
        </div>
      )}
    </div>
  );
}
