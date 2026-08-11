import { useState } from 'react';
import DashboardNav from '../components/DashboardNav';
import SecurityCard from '../components/SecurityCard';
import styles from './Dashboard.module.css';

/* ──────────────────────────────────────────────
   CSS-only animated shield for the main status card
   ────────────────────────────────────────────── */
function ShieldStatus() {
  return (
    <div className={styles.shieldStatus} aria-hidden="true">
      <div className={styles.shieldRing1} />
      <div className={styles.shieldRing2} />
      <div className={styles.shieldCore}>
        <span className={styles.shieldEmoji}>🛡️</span>
        <div className={styles.shieldScan} />
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────
   Threat level indicator
   ────────────────────────────────────────────── */
function ThreatLevel({ level = 'LOW' }) {
  const levels = ['LOW', 'MEDIUM', 'HIGH'];
  const colors = {
    LOW:    { active: '#10b981', glow: 'rgba(16,185,129,0.4)' },
    MEDIUM: { active: '#f59e0b', glow: 'rgba(245,158,11,0.4)' },
    HIGH:   { active: '#ef4444', glow: 'rgba(239,68,68,0.4)'  },
  };

  return (
    <div className={styles.threatLevel} role="region" aria-label="Threat level indicator">
      <h3 className={styles.threatTitle}>Threat Level</h3>
      <div className={styles.threatBars}>
        {levels.map((l) => {
          const isActive = l === level;
          const isBelow  =
            levels.indexOf(l) <= levels.indexOf(level);
          return (
            <div
              key={l}
              className={styles.threatBarWrap}
              aria-current={isActive ? 'true' : undefined}
            >
              <div
                className={styles.threatBar}
                style={{
                  background: isBelow
                    ? colors[level].active
                    : 'rgba(255,255,255,0.06)',
                  boxShadow: isActive
                    ? `0 0 12px ${colors[level].glow}`
                    : 'none',
                }}
              />
              <span
                className={styles.threatBarLabel}
                style={{ color: isActive ? colors[level].active : '#475569' }}
              >
                {l}
              </span>
            </div>
          );
        })}
      </div>
      <div className={styles.threatCurrentWrap}>
        <span
          className={styles.threatCurrent}
          style={{ color: colors[level].active }}
          aria-live="polite"
        >
          {level}
        </span>
        <span className={styles.threatCurrentLabel}>Current Status</span>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────
   Quick action cards data
   ────────────────────────────────────────────── */
const quickActions = [
  { id: 'analyze-message',  icon: '💬', label: 'Analyze Message',  desc: 'Check a suspicious message for scam patterns',   color: '#00d4ff' },
  { id: 'analyze-voice',    icon: '🎙️', label: 'Analyze Voice',    desc: 'Detect deepfake or impersonation in voice calls', color: '#7c3aed' },
  { id: 'check-link',       icon: '🔗', label: 'Check Link',       desc: 'Verify if a URL is safe or malicious',            color: '#10b981' },
  { id: 'analyze-document', icon: '📄', label: 'Analyze Document', desc: 'Scan a document for hidden threats',              color: '#f59e0b' },
];

/* ──────────────────────────────────────────────
   Dashboard Page
   ────────────────────────────────────────────── */
export default function Dashboard() {
  const [activeAction, setActiveAction] = useState(null);

  const handleActionClick = (id) => {
    setActiveAction(id);
    /* Future: open a modal or navigate to the analysis page */
    setTimeout(() => setActiveAction(null), 2000);
  };

  return (
    <div className={styles.page}>
      <DashboardNav />

      <div className={styles.layout}>
        {/* ── Main content ── */}
        <main className={styles.main} id="main-content">
          {/* Welcome header */}
          <div className={styles.welcomeBar}>
            <div>
              <h1 className={styles.welcomeTitle}>Welcome to KAVACH</h1>
              <p className={styles.welcomeDesc}>
                Your digital safety status is{' '}
                <span className={styles.welcomeSafe}>protected</span>. No threats detected.
              </p>
            </div>
            <div className={styles.welcomeTime}>
              <span className={styles.welcomeTimeDot} />
              <span className={styles.welcomeTimeLabel}>Live Monitoring</span>
            </div>
          </div>

          {/* ── Security overview cards ── */}
          <section aria-label="Security overview" className={styles.cardsSection}>
            <div className={styles.statsGrid}>
              <SecurityCard
                icon="🛡️"
                label="Security Status"
                value="Safe"
                status="Protected"
                variant="green"
              />
              <SecurityCard
                icon="⚠️"
                label="Threats Detected"
                value="0"
                status="All Clear"
                variant="blue"
              />
              <SecurityCard
                icon="🔍"
                label="Scans Completed"
                value="0"
                status="Ready"
                variant="purple"
              />
              <SecurityCard
                icon="⚡"
                label="Protection Level"
                value="Active"
                status="Max Shield"
                variant="orange"
              />
            </div>
          </section>

          {/* ── Main status card + Threat level ── */}
          <div className={styles.statusRow}>
            {/* Big status card */}
            <section className={styles.bigStatusCard} aria-label="Digital environment status">
              <div className={styles.bigStatusLeft}>
                <ShieldStatus />
              </div>
              <div className={styles.bigStatusRight}>
                <span className={styles.bigStatusBadge}>
                  <span className={styles.bigStatusDot} />
                  SYSTEM ACTIVE
                </span>
                <h2 className={styles.bigStatusTitle}>
                  Your Digital Environment<br />
                  <span className={styles.bigStatusAccent}>is Secure</span>
                </h2>
                <p className={styles.bigStatusDesc}>
                  KAVACH is actively monitoring your digital environment for threats.
                  All protection modules are online and operational.
                </p>
                <div className={styles.bigStatusModules}>
                  {['Scam Detection', 'Phishing Guard', 'Voice Analysis', 'Document Shield'].map((m) => (
                    <span key={m} className={styles.moduleChip}>
                      <span className={styles.moduleChipDot} />
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            </section>

            {/* Threat level */}
            <ThreatLevel level="LOW" />
          </div>

          {/* ── Quick actions ── */}
          <section aria-label="Quick actions" className={styles.quickSection}>
            <h2 className={styles.sectionTitle}>Quick Actions</h2>
            <div className={styles.quickGrid}>
              {quickActions.map((action) => (
                <button
                  key={action.id}
                  id={`action-${action.id}`}
                  className={`${styles.quickCard} ${activeAction === action.id ? styles.quickCardActive : ''}`}
                  onClick={() => handleActionClick(action.id)}
                  aria-label={action.label}
                >
                  <div
                    className={styles.quickIcon}
                    style={{
                      background: `${action.color}18`,
                      border: `1px solid ${action.color}30`,
                    }}
                  >
                    <span>{action.icon}</span>
                  </div>
                  <h3 className={styles.quickLabel}>{action.label}</h3>
                  <p className={styles.quickDesc}>{action.desc}</p>
                  {activeAction === action.id && (
                    <span className={styles.quickComingSoon}>Coming Soon</span>
                  )}
                  <div
                    className={styles.quickArrow}
                    style={{ color: action.color }}
                    aria-hidden="true"
                  >
                    →
                  </div>
                </button>
              ))}
            </div>
          </section>

          {/* ── Recent activity ── */}
          <section aria-label="Recent activity" className={styles.activitySection}>
            <div className={styles.activityHeader}>
              <h2 className={styles.sectionTitle}>Recent Activity</h2>
              <span className={styles.activityBadge}>0 Events</span>
            </div>
            <div className={styles.activityEmpty}>
              <div className={styles.activityEmptyIcon}>✅</div>
              <h3 className={styles.activityEmptyTitle}>No Suspicious Activity Detected</h3>
              <p className={styles.activityEmptyDesc}>
                Your digital environment has been quiet. KAVACH will alert you instantly
                if any suspicious activity is detected.
              </p>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
