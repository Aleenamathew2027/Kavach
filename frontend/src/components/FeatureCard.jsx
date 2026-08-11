import styles from './FeatureCard.module.css';

/**
 * FeatureCard – displays a single security feature on the landing page
 *
 * @param {string} icon      - Emoji or icon character
 * @param {string} title     - Feature title
 * @param {string} desc      - Feature description
 * @param {string} color     - Accent color key: 'blue' | 'purple' | 'green' | 'orange' | 'pink' | 'teal'
 */
export default function FeatureCard({ icon, title, desc, color = 'blue' }) {
  return (
    <article className={`${styles.card} ${styles[color]}`} aria-label={title}>
      <div className={styles.iconWrap}>
        <span className={styles.icon} role="img" aria-hidden="true">{icon}</span>
      </div>
      <h3 className={styles.title}>{title}</h3>
      <p className={styles.desc}>{desc}</p>
      <div className={styles.glowLine} />
    </article>
  );
}
