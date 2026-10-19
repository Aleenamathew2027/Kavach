import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, getToken, clearAuth } from '../services/api';
import styles from './UserDashboard.module.css';

export default function UserDashboard() {
  const navigate = useNavigate();

  const [userProfile, setUserProfile] = useState(null);
  const [securitySummary, setSecuritySummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [recentReports, setRecentReports] = useState([]);
  const [guardianCode, setGuardianCode] = useState(null);
  const [guardianExpiry, setGuardianExpiry] = useState(null);
  const [codeMsg, setCodeMsg] = useState('');
  const [codeError, setCodeError] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [profile, summary, reports, alertData] = await Promise.all([
          api.getMe().catch(() => null),
          api.getSecuritySummary().catch(() => null),
          api.getUserReports().catch(() => []),
          api.getSecurityAlerts().catch(() => []),
        ]);
        if (profile) setUserProfile(profile);
        if (summary) setSecuritySummary(summary);
        if (Array.isArray(reports)) setRecentReports(reports.slice(0, 3));
        if (Array.isArray(alertData)) setAlerts(alertData.slice(0, 4));
      } catch (err) {
        console.error('Error loading user dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleLogout = () => {
    clearAuth();
    navigate('/login', { replace: true });
  };

  const handleGenerateCode = async () => {
    try {
      setCodeMsg('Generating code…');
      setCodeError(false);
      const data = await api.generateGuardianCode();
      setGuardianCode(data.code);
      setGuardianExpiry(
        new Date(data.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      );
      setCodeMsg('Code active for 24 hours. Share this with your trusted guardian.');
    } catch (err) {
      console.error('Guardian generation error:', err);
      setCodeError(true);
      setCodeMsg(err.message || 'Unable to generate your guardian access code. Please try again.');
    }
  };

  const handleRevokeCode = async () => {
    try {
      setCodeError(false);
      await api.revokeGuardianCode();
      setGuardianCode(null);
      setGuardianExpiry(null);
      setCodeMsg('Guardian access code revoked.');
    } catch (err) {
      console.error('Guardian revoke error:', err);
      setCodeError(true);
      setCodeMsg(err.message || 'Unable to revoke code. Please try again.');
    }
  };

  const handleCopyCode = () => {
    if (!guardianCode) return;
    navigator.clipboard.writeText(guardianCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadUserPdf = async (reportId) => {
    setDownloadingId(reportId);
    try {
      const token = getToken();
      const url = api.downloadUserReportPdf(reportId);
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error('Download failed');
      const blob = await response.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `KAVACH_Incident_Report_${reportId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error('PDF download error:', err);
      alert('Unable to download the report. Please try again.');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleMarkAlertRead = async (alertId) => {
    try {
      await api.markAlertRead(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, is_read: true } : a))
      );
    } catch (err) {
      console.error('Error marking alert as read:', err);
    }
  };

  // Threat & Score Calculations
  const threats = securitySummary?.threats_detected ?? 0;
  const suspiciousMessages = securitySummary?.suspicious_messages ?? 0;
  const suspiciousLinks = securitySummary?.suspicious_links ?? 0;
  const suspiciousDocuments = securitySummary?.suspicious_documents ?? 0;
  const totalScans = securitySummary?.total_scans ?? 0;
  const totalSuspicious = suspiciousMessages + suspiciousLinks + suspiciousDocuments;
  const safeCount = Math.max(0, totalScans - threats - totalSuspicious);

  const isAttentionRequired =
    threats > 0 || (securitySummary && securitySummary.active_threat_level === 'HIGH');

  // Compute 0-100 Security Safety Score
  let securityScore = 100;
  if (threats > 0) {
    securityScore = Math.max(25, 100 - threats * 30 - totalSuspicious * 8);
  } else if (totalSuspicious > 0) {
    securityScore = Math.max(68, 100 - totalSuspicious * 7);
  } else {
    securityScore = totalScans > 0 ? 100 : 98;
  }

  // SVG Circular Meter math
  const ringRadius = 54;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringDashOffset = ringCircumference - (securityScore / 100) * ringCircumference;

  // Unread alerts count
  const unreadAlertsCount = alerts.filter((a) => !a.is_read).length;

  const getInitials = (name) => {
    if (!name) return 'U';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    return parts[0][0].toUpperCase();
  };

  const userName = userProfile?.full_name || 'Kavach Citizen';

  return (
    <div className={styles.dashboardLayout}>
      {/* ── DESKTOP SIDEBAR NAVIGATION (#112250) ── */}
      <aside className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <Link to="/user/dashboard" className={styles.brandLogo}>
            KAVACH<span className={styles.brandDot}>.</span>
          </Link>
          <span className={styles.brandTagline}>AI CYBER GUARDIAN</span>
        </div>

        {/* User Badge in Sidebar */}
        <div className={styles.userBadgeCard}>
          <div className={styles.userAvatarMini}>{getInitials(userName)}</div>
          <div className={styles.userBadgeInfo}>
            <span className={styles.userBadgeName}>{userName}</span>
            <span className={styles.userBadgeRole}>SECURE CITIZEN</span>
          </div>
        </div>

        {/* Sidebar Nav Items */}
        <nav className={styles.sidebarNav} aria-label="Sidebar Navigation">
          <span className={styles.navSectionLabel}>NAVIGATION</span>
          <Link
            to="/user/dashboard"
            className={`${styles.sidebarLink} ${styles.sidebarLinkActive}`}
          >
            <span className={styles.navIcon}>❖</span>
            <span>Dashboard</span>
          </Link>
          <Link to="/user/messages" className={styles.sidebarLink}>
            <span className={styles.navIcon}>⌕</span>
            <span>Scan &amp; Check</span>
          </Link>
          <Link to="/user/alerts" className={styles.sidebarLink}>
            <span className={styles.navIcon}>🔔</span>
            <span>Alerts</span>
          </Link>
          <Link to="/user/assistant" className={styles.sidebarLink}>
            <span className={styles.navIcon}>🛡️</span>
            <span>AI Assistant</span>
          </Link>
          <a href="#guardian-section" className={styles.sidebarLink}>
            <span className={styles.navIcon}>👥</span>
            <span>Guardian</span>
          </a>
          <a href="#reports-section" className={styles.sidebarLink}>
            <span className={styles.navIcon}>📄</span>
            <span>Incident Reports</span>
          </a>
          <Link to="/user/security" className={styles.sidebarLink}>
            <span className={styles.navIcon}>🔒</span>
            <span>Security Center</span>
          </Link>
          <Link to="/user/profile" className={styles.sidebarLink}>
            <span className={styles.navIcon}>⚙</span>
            <span>Settings</span>
          </Link>
        </nav>

        {/* Sidebar Bottom Telemetry & Logout */}
        <div className={styles.sidebarFooter}>
          <div className={styles.systemStatusPill}>
            <span className={styles.statusLiveDot} />
            <span>Shield Active • 24/7</span>
          </div>
          <button
            type="button"
            className={styles.sidebarLogoutBtn}
            onClick={handleLogout}
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── MOBILE TOP BAR (< 1080px) ── */}
      <div className={styles.mobileTopBar}>
        <Link to="/user/dashboard" className={styles.brandLogo} style={{ fontSize: '18px' }}>
          KAVACH<span className={styles.brandDot}>.</span>
        </Link>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Link to="/user/alerts" className={styles.headerAlertBtn} style={{ padding: '6px 10px' }}>
            🔔
            {unreadAlertsCount > 0 && (
              <span className={styles.alertCountBadge}>{unreadAlertsCount}</span>
            )}
          </Link>
          <button
            type="button"
            className={styles.mobileMenuBtn}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>

      {/* ── MOBILE DRAWER OVERLAY ── */}
      <div
        className={`${styles.mobileDrawerOverlay} ${
          mobileMenuOpen ? styles.mobileDrawerOpen : ''
        }`}
      >
        <Link
          to="/user/dashboard"
          className={`${styles.mobileDrawerLink} ${styles.mobileDrawerLinkActive}`}
          onClick={() => setMobileMenuOpen(false)}
        >
          Dashboard
        </Link>
        <Link
          to="/user/messages"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Scan &amp; Check
        </Link>
        <Link
          to="/user/alerts"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Alerts {unreadAlertsCount > 0 ? `(${unreadAlertsCount})` : ''}
        </Link>
        <Link
          to="/user/assistant"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          AI Assistant
        </Link>
        <a
          href="#guardian-section"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Guardian Access
        </a>
        <a
          href="#reports-section"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Incident Reports
        </a>
        <Link
          to="/user/security"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Security Center
        </Link>
        <Link
          to="/user/profile"
          className={styles.mobileDrawerLink}
          onClick={() => setMobileMenuOpen(false)}
        >
          Settings
        </Link>
        <button
          type="button"
          className={styles.sidebarLogoutBtn}
          style={{ marginTop: '16px' }}
          onClick={handleLogout}
        >
          Sign Out ({userName})
        </button>
      </div>

      {/* ── MAIN CONTENT CANVAS ── */}
      <div className={styles.mainContent}>
        {/* Top Header Surface */}
        <header className={styles.topHeader}>
          <div className={styles.headerGreeting}>
            <h1 className={styles.greetingTitle}>
              Welcome back, {userName}
            </h1>
            <p className={styles.greetingSub}>
              System Shield Active • Continuous Threat Telemetry &amp; Detection
            </p>
          </div>

          <div className={styles.headerActions}>
            <Link to="/user/alerts" className={styles.headerAlertBtn} title="View Alerts">
              <span>🔔</span>
              <span>Alerts</span>
              {unreadAlertsCount > 0 && (
                <span className={styles.alertCountBadge}>{unreadAlertsCount}</span>
              )}
            </Link>

            <a href="#guardian-section" className={styles.headerCodeBtn}>
              + Guardian Code
            </a>

            <Link
              to="/user/profile"
              className={styles.userAvatarMini}
              style={{ width: '38px', height: '38px', textDecoration: 'none' }}
              title="View Profile Settings"
            >
              {getInitials(userName)}
            </Link>
          </div>
        </header>

        {/* Dashboard Scrollable Body */}
        <main className={styles.dashboardBody}>
          {/* ── HERO GRID: SECURITY SCORE & THREAT BREAKDOWN ── */}
          <section className={styles.heroGrid}>
            {/* Main Security Score Card */}
            <div className={styles.scoreCard}>
              <div>
                <span className={styles.statLabel}>KAVACH SENTINEL TELEMETRY</span>
                <div style={{ marginTop: '12px' }} className={styles.scoreTopRow}>
                  {/* Large Circular Score Ring */}
                  <div className={styles.scoreRingWrapper}>
                    <svg className={styles.scoreRingSvg} viewBox="0 0 128 128">
                      <circle
                        className={styles.scoreRingTrack}
                        cx="64"
                        cy="64"
                        r={ringRadius}
                        strokeWidth="8"
                        fill="transparent"
                      />
                      <circle
                        className={styles.scoreRingFill}
                        cx="64"
                        cy="64"
                        r={ringRadius}
                        strokeWidth="8"
                        fill="transparent"
                        strokeDasharray={ringCircumference}
                        strokeDashoffset={ringDashOffset}
                        strokeLinecap="round"
                        style={
                          isAttentionRequired
                            ? { stroke: '#ef4444' }
                            : { stroke: 'var(--kavach-quicksand)' }
                        }
                      />
                    </svg>
                    <div className={styles.scoreCenterText}>
                      <span className={styles.scoreBigNumber}>{securityScore}</span>
                      <span className={styles.scoreTotalLabel}>/ 100</span>
                    </div>
                  </div>

                  {/* Score Details & Status Badge */}
                  <div className={styles.scoreContent}>
                    <span
                      className={`${styles.statusPillBadge} ${
                        isAttentionRequired ? styles.statusAttention : styles.statusProtected
                      }`}
                    >
                      {isAttentionRequired ? '⚠ ATTENTION REQUIRED' : '✓ PROTECTED • OPTIMAL'}
                    </span>
                    <h2 className={styles.scoreTitle}>
                      {isAttentionRequired
                        ? 'High-Risk Threats Flagged'
                        : 'Your Digital Perimeter is Secure'}
                    </h2>
                    <p className={styles.scoreExplanation}>
                      {isAttentionRequired
                        ? `${threats} critical scam or phishing pattern(s) identified in your security scans. Review details immediately.`
                        : 'Continuous ML heuristic sentinels active across incoming messages, web domains, and document attachments.'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Score Card Footer Actions */}
              <div className={styles.scoreActions}>
                <Link to="/user/security" className={styles.primaryActionBtn}>
                  View Security Details →
                </Link>
                <Link to="/user/messages" className={styles.secondaryActionBtn}>
                  Scan New Content
                </Link>
              </div>
            </div>

            {/* Top Threat Telemetry Matrix */}
            <div className={styles.threatMatrixCard}>
              <div>
                <div className={styles.sectionHeader} style={{ marginBottom: '18px' }}>
                  <h3 className={styles.sectionTitle}>
                    THREAT MATRIX <span className={styles.sectionTitleAccent}>TELEMETRY</span>
                  </h3>
                  <span className={styles.sectionSubtitle}>Real-time scan signals</span>
                </div>

                <div className={styles.threatList}>
                  {/* Threat 1: Phishing */}
                  <div className={styles.threatItem}>
                    <div className={styles.threatItemHeader}>
                      <span className={styles.threatName}>Phishing &amp; Deceptive URLs</span>
                      <span className={styles.threatCount}>{suspiciousLinks} Flagged</span>
                    </div>
                    <div className={styles.threatProgressTrack}>
                      <div
                        className={styles.threatProgressFill}
                        style={{
                          width: `${Math.min(
                            100,
                            totalScans > 0 ? (suspiciousLinks / Math.max(1, totalScans)) * 100 : 0
                          )}%`,
                        }}
                      />
                    </div>
                  </div>

                  {/* Threat 2: Scam Messages */}
                  <div className={styles.threatItem}>
                    <div className={styles.threatItemHeader}>
                      <span className={styles.threatName}>Scam Messages &amp; SMS Smishing</span>
                      <span className={styles.threatCount}>{suspiciousMessages} Flagged</span>
                    </div>
                    <div className={styles.threatProgressTrack}>
                      <div
                        className={styles.threatProgressFill}
                        style={{
                          width: `${Math.min(
                            100,
                            totalScans > 0 ? (suspiciousMessages / Math.max(1, totalScans)) * 100 : 0
                          )}%`,
                        }}
                      />
                    </div>
                  </div>

                  {/* Threat 3: Suspicious Documents */}
                  <div className={styles.threatItem}>
                    <div className={styles.threatItemHeader}>
                      <span className={styles.threatName}>Document &amp; File Attachments</span>
                      <span className={styles.threatCount}>{suspiciousDocuments} Flagged</span>
                    </div>
                    <div className={styles.threatProgressTrack}>
                      <div
                        className={styles.threatProgressFill}
                        style={{
                          width: `${Math.min(
                            100,
                            totalScans > 0
                              ? (suspiciousDocuments / Math.max(1, totalScans)) * 100
                              : 0
                          )}%`,
                        }}
                      />
                    </div>
                  </div>

                  {/* Threat 4: QR Scams */}
                  <div className={styles.threatItem}>
                    <div className={styles.threatItemHeader}>
                      <span className={styles.threatName}>QR Scams &amp; UPI Payment Traps</span>
                      <span className={styles.threatCount}>
                        {suspiciousDocuments > 0 ? 1 : 0} Monitored
                      </span>
                    </div>
                    <div className={styles.threatProgressTrack}>
                      <div
                        className={styles.threatProgressFill}
                        style={{
                          width: `${suspiciousDocuments > 0 ? 35 : 0}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '11px', color: 'var(--kavach-shellstone)', opacity: 0.7 }}>
                Calculated dynamically from verified PostgreSQL security logs.
              </div>
            </div>
          </section>

          {/* ── STATISTICS ROW (4 REFINED METRICS) ── */}
          <section>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>
                AUDIT <span className={styles.sectionTitleAccent}>STATISTICS</span>
              </h2>
              <span className={styles.sectionSubtitle}>Database verified metrics</span>
            </div>

            <div className={styles.statsGrid} style={{ marginTop: '16px' }}>
              <div className={styles.statCard}>
                <span className={styles.statLabel}>TOTAL SCANS EXECUTED</span>
                <span className={styles.statValue}>{totalScans}</span>
                <span className={styles.statSubtext}>Across messages, links &amp; files</span>
              </div>

              <div className={styles.statCard}>
                <span className={styles.statLabel}>SAFE CONTENT VERIFIED</span>
                <span className={styles.statValue} style={{ color: 'var(--kavach-swan-wing)' }}>
                  {safeCount}
                </span>
                <span className={styles.statSubtext}>Zero scam indicators found</span>
              </div>

              <div className={styles.statCard}>
                <span className={styles.statLabel}>SUSPICIOUS DETECTIONS</span>
                <span className={styles.statValue} style={{ color: 'var(--kavach-quicksand)' }}>
                  {totalSuspicious}
                </span>
                <span className={styles.statSubtext}>Social engineering flags</span>
              </div>

              <div className={styles.statCard}>
                <span className={styles.statLabel}>HIGH RISK THREATS</span>
                <span
                  className={styles.statValue}
                  style={threats > 0 ? { color: '#fca5a5' } : { color: 'var(--kavach-swan-wing)' }}
                >
                  {threats}
                </span>
                <span className={styles.statSubtext}>
                  {threats > 0 ? 'Urgent action required' : 'Zero active breaches'}
                </span>
              </div>
            </div>
          </section>

          {/* ── QUICK ACTIONS (DETECTION SCANNERS) ── */}
          <section>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>
                DETECTION <span className={styles.sectionTitleAccent}>SCANNERS</span>
              </h2>
              <span className={styles.sectionSubtitle}>
                Verify suspicious communication before interacting
              </span>
            </div>

            <div className={styles.scannersGrid} style={{ marginTop: '16px' }}>
              {/* Card 1: Message */}
              <Link to="/user/messages" className={styles.scannerCard}>
                <div>
                  <div className={styles.scannerHeader}>
                    <div className={styles.scannerIconWrap}>💬</div>
                    <span className={styles.scannerCategory}>COMMUNICATION</span>
                  </div>
                  <h3 className={styles.scannerTitle}>Message Scam Detector</h3>
                  <p className={styles.scannerDesc}>
                    Analyze SMS, WhatsApp, and emails for urgency manipulation, bank impersonation,
                    and OTP theft attempts.
                  </p>
                </div>
                <div className={styles.scannerAction}>
                  <span>Scan Message</span>
                  <span>→</span>
                </div>
              </Link>

              {/* Card 2: Link */}
              <Link to="/user/link-checker" className={styles.scannerCard}>
                <div>
                  <div className={styles.scannerHeader}>
                    <div className={styles.scannerIconWrap}>🔗</div>
                    <span className={styles.scannerCategory}>WEB INTEGRITY</span>
                  </div>
                  <h3 className={styles.scannerTitle}>Link Safety Checker</h3>
                  <p className={styles.scannerDesc}>
                    Inspect shortened URLs, typosquatting domains, and credential-harvesting
                    landing pages safely.
                  </p>
                </div>
                <div className={styles.scannerAction}>
                  <span>Verify Link</span>
                  <span>→</span>
                </div>
              </Link>

              {/* Card 3: Document */}
              <Link to="/user/document-checker" className={styles.scannerCard}>
                <div>
                  <div className={styles.scannerHeader}>
                    <div className={styles.scannerIconWrap}>📄</div>
                    <span className={styles.scannerCategory}>ATTACHMENTS</span>
                  </div>
                  <h3 className={styles.scannerTitle}>Document Scanner</h3>
                  <p className={styles.scannerDesc}>
                    Upload suspicious PDF, DOCX, or invoices to extract and analyze hidden URLs and
                    scam wording via OCR.
                  </p>
                </div>
                <div className={styles.scannerAction}>
                  <span>Inspect Document</span>
                  <span>→</span>
                </div>
              </Link>

              {/* Card 4: QR Code */}
              <Link to="/user/document-checker" className={styles.scannerCard}>
                <div>
                  <div className={styles.scannerHeader}>
                    <div className={styles.scannerIconWrap}>📷</div>
                    <span className={styles.scannerCategory}>PAYMENT SENTRY</span>
                  </div>
                  <h3 className={styles.scannerTitle}>QR Code Threat Detector</h3>
                  <p className={styles.scannerDesc}>
                    Decode and audit UPI payment QR codes to prevent unauthorized debit collect
                    requests and reverse frauds.
                  </p>
                </div>
                <div className={styles.scannerAction}>
                  <span>Audit QR Code</span>
                  <span>→</span>
                </div>
              </Link>
            </div>
          </section>

          {/* ── KAVACH AI ASSISTANT PROMO CARD ── */}
          <section className={styles.aiPromoCard}>
            <div className={styles.aiPromoLeft}>
              <div className={styles.aiPromoIcon}>🛡️</div>
              <div>
                <span className={styles.statLabel} style={{ color: 'var(--kavach-quicksand)' }}>
                  INTELLIGENT DIGITAL DEFENSE
                </span>
                <h3 className={styles.aiPromoTitle}>KAVACH AI Assistant</h3>
                <p className={styles.aiPromoDesc}>
                  Ask anything about cybersecurity, scams, or KAVACH.
                </p>
              </div>
            </div>

            <Link to="/user/assistant" className={styles.aiPromoBtn}>
              <span>Open Assistant</span>
              <span>→</span>
            </Link>
          </section>

          {/* ── DUAL COLUMN SECTION: ALERTS & SENTINELS ── */}
          <section className={styles.dualRow}>
            {/* Column 1: Security Alerts Panel */}
            <div className={styles.panelCard}>
              <div className={styles.sectionHeader}>
                <h3 className={styles.sectionTitle}>
                  SECURITY <span className={styles.sectionTitleAccent}>ALERTS</span>
                </h3>
                <Link to="/user/alerts" className={styles.sectionLink}>
                  View All ({alerts.length}) →
                </Link>
              </div>

              {loading ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--kavach-shellstone)' }}>
                  Loading security alerts…
                </div>
              ) : alerts.length === 0 ? (
                <div className={styles.emptyAlertsState}>
                  <span>🛡️</span>
                  <strong style={{ color: 'var(--kavach-swan-wing)' }}>All Clear</strong>
                  <p style={{ margin: 0, fontSize: '12px' }}>
                    No security alerts triggered. Scanned interactions have passed safely.
                  </p>
                </div>
              ) : (
                <div className={styles.alertList}>
                  {alerts.map((alert) => (
                    <div key={alert.id} className={styles.alertItem}>
                      <div className={styles.alertLeft}>
                        <div className={styles.alertHeaderRow}>
                          {!alert.is_read && <span className={styles.alertUnreadDot} title="Unread Alert" />}
                          <span className={styles.alertItemTitle}>{alert.title}</span>
                        </div>
                        <p className={styles.alertItemMessage}>{alert.message}</p>
                        <span className={styles.alertItemTime}>
                          {new Date(alert.created_at).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </span>
                      </div>

                      <span
                        className={`${styles.alertSeverityBadge} ${
                          alert.severity === 'HIGH'
                            ? styles.severityHigh
                            : alert.severity === 'MEDIUM'
                            ? styles.severityMedium
                            : styles.severityLow
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Column 2: Active Sentinels (Security Timeline) */}
            <div className={styles.panelCard}>
              <div className={styles.sectionHeader}>
                <h3 className={styles.sectionTitle}>
                  DEFENSE <span className={styles.sectionTitleAccent}>SENTINELS</span>
                </h3>
                <span className={styles.sectionSubtitle}>Automated protection active</span>
              </div>

              <div className={styles.sentinelsList}>
                <div className={styles.sentinelItem}>
                  <div className={styles.sentinelInfo}>
                    <span className={styles.sentinelTitle}>Heuristic Scam Filter</span>
                    <span className={styles.sentinelSub}>Real-time SMS &amp; WhatsApp Analysis</span>
                  </div>
                  <span className={styles.sentinelPill}>ACTIVE</span>
                </div>

                <div className={styles.sentinelItem}>
                  <div className={styles.sentinelInfo}>
                    <span className={styles.sentinelTitle}>Zero-Day URL Verification Sentry</span>
                    <span className={styles.sentinelSub}>Domain Spoofing &amp; SSL Analysis</span>
                  </div>
                  <span className={styles.sentinelPill}>ACTIVE</span>
                </div>

                <div className={styles.sentinelItem}>
                  <div className={styles.sentinelInfo}>
                    <span className={styles.sentinelTitle}>Document &amp; OCR Link Extractor</span>
                    <span className={styles.sentinelSub}>Multi-Stage Content Inspection</span>
                  </div>
                  <span className={styles.sentinelPill}>ACTIVE</span>
                </div>

                <div className={styles.sentinelItem}>
                  <div className={styles.sentinelInfo}>
                    <span className={styles.sentinelTitle}>PostgreSQL Audit Vault</span>
                    <span className={styles.sentinelSub}>Encrypted Incident Logs</span>
                  </div>
                  <span className={styles.sentinelPill}>ACTIVE</span>
                </div>
              </div>
            </div>
          </section>

          {/* ── TRUSTED GUARDIAN ACCESS PANEL ── */}
          <section id="guardian-section" className={styles.guardianPanel}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>
                TRUSTED <span className={styles.sectionTitleAccent}>GUARDIAN ACCESS</span>
              </h2>
              <span className={styles.sectionSubtitle}>Family safety network</span>
            </div>

            <p className={styles.guardianIntro}>
              Share temporary access with someone you trust. Your authorized guardian can review
              security telemetry and threat alerts to assist you, without ever seeing your private
              passwords, credentials, or personal message transcripts.
            </p>

            {guardianCode ? (
              <div>
                <div className={styles.codeDisplayBox}>
                  <div>
                    <span className={styles.codeLabel}>YOUR 6-DIGIT ACCESS CODE</span>
                    <div className={styles.codeDigits}>{guardianCode}</div>
                  </div>
                  <button type="button" className={styles.copyCodeBtn} onClick={handleCopyCode}>
                    {copied ? '✓ COPIED' : 'COPY ACCESS CODE'}
                  </button>
                </div>

                <div className={styles.codeNotice}>
                  Active for: <strong>24 hours (Expires at {guardianExpiry})</strong>
                </div>
                <div style={{ fontSize: '12px', color: '#fca5a5', marginTop: '6px' }}>
                  ⚠ Only share this temporary access code with someone you personally trust.
                </div>

                <div>
                  <button type="button" className={styles.revokeCodeBtn} onClick={handleRevokeCode}>
                    Revoke Active Code
                  </button>
                </div>
              </div>
            ) : (
              <div>
                {codeMsg && (
                  <p
                    className={`${styles.codeStatusMsg} ${
                      codeError ? styles.codeMsgError : styles.codeMsgSuccess
                    }`}
                  >
                    {codeMsg}
                  </p>
                )}
                <button
                  type="button"
                  className={styles.generateCodeBtn}
                  onClick={handleGenerateCode}
                >
                  Generate Guardian Access Code
                </button>
              </div>
            )}
          </section>

          {/* ── CYBER INCIDENT REPORTS SECTION ── */}
          <section id="reports-section" className={styles.reportsSection}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>
                CYBER INCIDENT <span className={styles.sectionTitleAccent}>REPORTS</span>
              </h2>
              <span className={styles.sectionSubtitle}>
                Auto-generated documentation drafts for high-risk threats
              </span>
            </div>

            {recentReports.length === 0 ? (
              <div
                style={{
                  background: 'rgba(26, 46, 94, 0.3)',
                  border: '1px solid rgba(217, 203, 194, 0.1)',
                  borderRadius: '6px',
                  padding: '24px 28px',
                  color: 'var(--kavach-shellstone)',
                  fontSize: '13px',
                }}
              >
                No high-risk incident reports on record. When a critical threat is intercepted by
                KAVACH, a formal cybercrime complaint draft and PDF report will be prepared here
                automatically.
              </div>
            ) : (
              <div className={styles.reportsList}>
                {recentReports.map((rep) => (
                  <div key={rep.report_id} className={styles.reportCard}>
                    <div className={styles.reportCardHeader}>
                      <div>
                        <span className={styles.reportBadge}>HIGH RISK INCIDENT DETECTED</span>
                        <div className={styles.reportIdText}>Report ID: {rep.report_id}</div>
                      </div>
                      <span className={styles.reportTypeLabel}>
                        {rep.incident_type?.replace(/_/g, ' ')}
                      </span>
                    </div>

                    <p className={styles.reportSummaryText}>
                      A Cyber Security Incident Report / Complaint Draft has been automatically
                      compiled. This document records digital evidence and threat telemetry suitable
                      for filing with national cybercrime authorities or your banking institution.
                    </p>

                    <div className={styles.reportActionsRow}>
                      <button
                        type="button"
                        className={styles.reportDownloadBtn}
                        onClick={() => handleDownloadUserPdf(rep.report_id)}
                        disabled={downloadingId === rep.report_id}
                      >
                        {downloadingId === rep.report_id ? '⟳ Downloading PDF…' : '⬇ Download PDF Report'}
                      </button>
                      <Link to="/user/alerts" className={styles.reportViewAlertsBtn}>
                        View Correlated Alerts →
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </main>
      </div>
    </div>
  );
}
