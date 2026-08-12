import { useState, useEffect } from 'react';
import { api, getToken, getRole } from '../services/api';
import DashboardNav from '../components/DashboardNav';
import SecurityCard from '../components/SecurityCard';
import styles from './Dashboard.module.css';

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
          const isBelow  = levels.indexOf(l) <= levels.indexOf(level);
          return (
            <div key={l} className={styles.threatBarWrap} aria-current={isActive ? 'true' : undefined}>
              <div
                className={styles.threatBar}
                style={{
                  background: isBelow ? colors[level].active : 'rgba(255,255,255,0.06)',
                  boxShadow: isActive ? `0 0 12px ${colors[level].glow}` : 'none',
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

const quickActions = [
  { id: 'analyze-message',  icon: '💬', label: 'Analyze Message',  desc: 'Check a suspicious message for scam patterns',   color: '#00d4ff' },
  { id: 'analyze-voice',    icon: '🎙️', label: 'Analyze Voice',    desc: 'Detect deepfake or impersonation in voice calls', color: '#7c3aed' },
  { id: 'check-link',       icon: '🔗', label: 'Check Link',       desc: 'Verify if a URL is safe or malicious',            color: '#10b981' },
  { id: 'analyze-document', icon: '📄', label: 'Analyze Document', desc: 'Scan a document for hidden threats',              color: '#f59e0b' },
];

export default function Dashboard({ role: propRole }) {
  const [activeAction, setActiveAction] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [userProfile, setUserProfile] = useState(null);
  const [guardianCode, setGuardianCode] = useState(null);
  const [guardianExpiry, setGuardianExpiry] = useState(null);
  const [codeMsg, setCodeMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const role = propRole || getRole();
  const token = getToken();

  useEffect(() => {
    async function loadData() {
      if (!token) return;
      setLoading(true);
      try {
        if (role === 'admin') {
          const data = await api.getAdminDashboard();
          setDashboardData(data);
        } else if (role === 'guardian') {
          const data = await api.getGuardianDashboard();
          setDashboardData(data);
        } else {
          const data = await api.getUserDashboard();
          setDashboardData(data);
        }

        if (role !== 'guardian') {
          const userData = await api.getMe();
          setUserProfile(userData);
        }
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [role, token]);

  const handleActionClick = (id) => {
    setActiveAction(id);
    setTimeout(() => setActiveAction(null), 2000);
  };

  const handleGenerateGuardianCode = async () => {
    try {
      setCodeMsg('Generating code…');
      const data = await api.generateGuardianCode();
      setGuardianCode(data.code);
      setGuardianExpiry(new Date(data.expires_at).toLocaleTimeString());
      setCodeMsg('Code active for 24 hours. Share this with your trusted guardian.');
    } catch (err) {
      setCodeMsg(err.message || 'Failed to generate code.');
    }
  };

  const handleRevokeGuardianCode = async () => {
    try {
      await api.revokeGuardianCode();
      setGuardianCode(null);
      setGuardianExpiry(null);
      setCodeMsg('All guardian access codes have been revoked.');
    } catch (err) {
      setCodeMsg(err.message || 'Failed to revoke code.');
    }
  };

  return (
    <div className={styles.page}>
      <DashboardNav role={role} />

      <div className={styles.layout}>
        <main className={styles.main} id="main-content">
          {/* Welcome header */}
          <div className={styles.welcomeBar}>
            <div>
              <h1 className={styles.welcomeTitle}>
                {role === 'admin' && '🛡️ Administrator Control Panel'}
                {role === 'guardian' && '👁️ Guardian Monitoring Dashboard'}
                {role === 'user' && `Welcome, ${userProfile?.full_name || 'KAVACH User'}`}
              </h1>
              <p className={styles.welcomeDesc}>
                {role === 'admin' && 'System-wide monitoring, user management, and security infrastructure status.'}
                {role === 'guardian' && `Authorized view for protected user: ${dashboardData?.guarded_user?.full_name || 'Guarded User'} (${dashboardData?.guarded_user?.email || ''})`}
                {role === 'user' && (
                  <>
                    Your digital safety status is{' '}
                    <span className={styles.welcomeSafe}>protected</span>. No active threats detected.
                  </>
                )}
              </p>
            </div>
            <div className={styles.welcomeTime}>
              <span className={styles.welcomeTimeDot} />
              <span className={styles.welcomeTimeLabel}>
                {role === 'admin' ? 'SYSTEM LIVE' : role === 'guardian' ? 'GUARDIAN LINKED' : 'Live Monitoring'}
              </span>
            </div>
          </div>

          {/* ── Security overview cards ── */}
          <section aria-label="Security overview" className={styles.cardsSection}>
            <div className={styles.statsGrid}>
              {role === 'admin' ? (
                <>
                  <SecurityCard
                    icon="👥"
                    label="Total Registered Users"
                    value={dashboardData?.total_users ?? '...'}
                    status="Active in PostgreSQL"
                    variant="green"
                  />
                  <SecurityCard
                    icon="🔗"
                    label="Active Guardian Links"
                    value={dashboardData?.active_guardian_links ?? '0'}
                    status="Verified Codes"
                    variant="blue"
                  />
                  <SecurityCard
                    icon="⚡"
                    label="Admin Account"
                    value="Active"
                    status={dashboardData?.admin_email || 'admin@kavach.com'}
                    variant="purple"
                  />
                  <SecurityCard
                    icon="🛡️"
                    label="System Status"
                    value="100%"
                    status="Operational"
                    variant="orange"
                  />
                </>
              ) : role === 'guardian' ? (
                <>
                  <SecurityCard
                    icon="🛡️"
                    label="Guarded Status"
                    value="Safe"
                    status={dashboardData?.security_status || 'Protected'}
                    variant="green"
                  />
                  <SecurityCard
                    icon="👤"
                    label="Guarded Account"
                    value={dashboardData?.guarded_user?.full_name || 'User'}
                    status={dashboardData?.guarded_user?.email || ''}
                    variant="blue"
                  />
                  <SecurityCard
                    icon="⏳"
                    label="Authorized Until"
                    value={dashboardData?.authorized_until ? new Date(dashboardData.authorized_until).toLocaleDateString() : 'Active'}
                    status="24-Hour Pass"
                    variant="purple"
                  />
                  <SecurityCard
                    icon="🚨"
                    label="Active Alerts"
                    value="0"
                    status="All Clear"
                    variant="orange"
                  />
                </>
              ) : (
                <>
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
                    icon="🔗"
                    label="Guardian Links"
                    value={dashboardData?.active_guardian_codes ?? 0}
                    status="Active Codes"
                    variant="purple"
                  />
                  <SecurityCard
                    icon="⚡"
                    label="Protection Level"
                    value="Active"
                    status="Max Shield"
                    variant="orange"
                  />
                </>
              )}
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
                  {role === 'admin' ? 'ADMIN PRIVILEGES' : role === 'guardian' ? 'GUARDIAN ACCESS' : 'PROTECTION ACTIVE'}
                </span>
                <h2 className={styles.bigStatusTitle}>
                  {role === 'admin' && 'KAVACH Infrastructure Operational'}
                  {role === 'guardian' && `Monitoring ${dashboardData?.guarded_user?.full_name || 'Protected User'}`}
                  {role === 'user' && 'Your Digital Environment is Secure'}
                </h2>
                <p className={styles.bigStatusDesc}>
                  {role === 'admin' && 'Real-time role enforcement, PostgreSQL transaction pools, and security analyzers are fully active.'}
                  {role === 'guardian' && 'You have authorized guardian visibility into this user\'s AI scam protection modules and threat alerts.'}
                  {role === 'user' && 'KAVACH AI models are actively guarding your messages, incoming calls, links, and transactions.'}
                </p>
                <div className={styles.bigStatusModules}>
                  {(dashboardData?.protection_modules || ['Scam Detection', 'Phishing Guard', 'Voice Analysis', 'Document Shield']).map((m) => (
                    <span key={m} className={styles.moduleChip}>
                      <span className={styles.moduleChipDot} />
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            </section>

            {/* Threat level */}
            <ThreatLevel level={dashboardData?.active_threat_level || 'LOW'} />
          </div>

          {/* ── User-specific Guardian Code Management Section ── */}
          {role === 'user' && (
            <section
              style={{
                background: 'rgba(4, 18, 13, 0.8)',
                border: '1px solid rgba(0, 255, 136, 0.15)',
                borderRadius: '16px',
                padding: '24px 28px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#e8fff5', margin: 0 }}>
                    🛡️ Guardian Access Code
                  </h3>
                  <p style={{ fontSize: '13px', color: '#64748b', margin: '4px 0 0' }}>
                    Generate a secure 6-digit access code for your trusted guardian (family member or supervisor).
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={handleGenerateGuardianCode}
                    style={{
                      background: 'linear-gradient(135deg, #00ff88, #00e5b0)',
                      color: '#010c09',
                      border: 'none',
                      borderRadius: '8px',
                      padding: '8px 16px',
                      fontWeight: 700,
                      fontSize: '13px',
                      cursor: 'pointer',
                    }}
                  >
                    + Generate 6-Digit Code
                  </button>
                  {guardianCode && (
                    <button
                      type="button"
                      onClick={handleRevokeGuardianCode}
                      style={{
                        background: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        color: '#ef4444',
                        borderRadius: '8px',
                        padding: '8px 16px',
                        fontWeight: 600,
                        fontSize: '13px',
                        cursor: 'pointer',
                      }}
                    >
                      Revoke Code
                    </button>
                  )}
                </div>
              </div>

              {guardianCode && (
                <div
                  style={{
                    background: 'rgba(0, 255, 136, 0.05)',
                    border: '1px dashed #00ff88',
                    borderRadius: '12px',
                    padding: '16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px',
                  }}
                >
                  <div>
                    <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '1px' }}>
                      Active Guardian Code
                    </span>
                    <div style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '8px', color: '#00ff88', fontFamily: 'monospace' }}>
                      {guardianCode}
                    </div>
                  </div>
                  <div style={{ fontSize: '13px', color: '#94a3b8', textAlign: 'right' }}>
                    <div>Expires at: <strong style={{ color: '#e8fff5' }}>{guardianExpiry}</strong></div>
                    <div style={{ color: '#00ff88', fontSize: '12px', marginTop: '4px' }}>Ready to share with guardian</div>
                  </div>
                </div>
              )}

              {codeMsg && !guardianCode && (
                <div style={{ fontSize: '13px', color: '#00ff88' }}>{codeMsg}</div>
              )}
            </section>
          )}

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
                Your digital environment is monitored by KAVACH. You will be alerted instantly
                if any scam attempts or malicious activities are detected.
              </p>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
