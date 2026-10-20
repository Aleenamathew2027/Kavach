import { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api, getToken } from '../services/api';
import GuardianLayout from '../components/GuardianLayout';
import styles from './GuardianDashboard.module.css';

export default function GuardianDashboard() {
  const navigate = useNavigate();

  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [highRiskPopupAlert, setHighRiskPopupAlert] = useState(null);
  const [dismissedAlertIds, setDismissedAlertIds] = useState(() => {
    try {
      const saved = sessionStorage.getItem('kavach_guardian_dismissed_alerts');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // Incident Reports state
  const [reports, setReports] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(true);
  const [reportsError, setReportsError] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportDetailLoading, setReportDetailLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);

  const loadReports = useCallback(async () => {
    setReportsLoading(true);
    setReportsError(null);
    try {
      const data = await api.getGuardianReports();
      setReports(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Error loading guardian reports:', err);
      setReportsError('Unable to load cyber incident reports. Please try again.');
    } finally {
      setReportsLoading(false);
    }
  }, []);

  const loadData = async () => {
    try {
      const data = await api.getGuardianDashboard();
      setGuardianData(data);

      // Check for active HIGH severity alerts that haven't been dismissed in this session
      if (data?.recent_alerts && data.recent_alerts.length > 0) {
        const activeHigh = data.recent_alerts.find(
          (a) => a.severity === 'HIGH' && !dismissedAlertIds.includes(a.id)
        );
        if (activeHigh) {
          setHighRiskPopupAlert(activeHigh);
        }
      }
    } catch (err) {
      console.error('Error loading guardian dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    loadReports();
    // Safe periodic polling every 12 seconds for new security incidents and reports
    const interval = setInterval(() => {
      loadData();
      loadReports();
    }, 12000);
    return () => clearInterval(interval);
  }, [dismissedAlertIds]);

  const handleDismissAlert = (alertId) => {
    const updated = [...dismissedAlertIds, alertId];
    setDismissedAlertIds(updated);
    sessionStorage.setItem('kavach_guardian_dismissed_alerts', JSON.stringify(updated));
    setHighRiskPopupAlert(null);
  };

  const handleViewReport = async (reportId) => {
    setReportDetailLoading(true);
    try {
      const detail = await api.getGuardianReportDetail(reportId);
      setSelectedReport(detail);
    } catch (err) {
      console.error('Error fetching report detail:', err);
      alert('Unable to load report details. Please try again.');
    } finally {
      setReportDetailLoading(false);
    }
  };

  const handleDownloadPdf = async (reportId) => {
    setDownloadingId(reportId);
    try {
      const token = getToken();
      const url = api.downloadGuardianReportPdf(reportId);
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error('Download failed');
      const blob = await response.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `KAVACH_Guardian_Report_${reportId}.pdf`;
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

  const getIncidentTypeLabel = (type) => {
    const labels = {
      SCAM_MESSAGE: 'Scam Message',
      PHISHING_LINK: 'Phishing Link',
      SUSPICIOUS_DOCUMENT: 'Suspicious Document',
      SUSPICIOUS_QR: 'QR Code Threat',
      MULTI_SIGNAL_SCAM: 'Multi-Signal Scam',
    };
    return labels[type] || type;
  };


  const protectedName = guardianData?.guarded_user?.full_name || 'Protected User';
  const protectedEmail = guardianData?.guarded_user?.email || '—';
  const isAttentionRequired = guardianData?.overall_status === 'ATTENTION REQUIRED';
  const stats = guardianData?.security_summary || {
    threats_detected: 0,
    suspicious_messages: 0,
    suspicious_links: 0,
    suspicious_documents: 0,
  };
  const alerts = guardianData?.recent_alerts || [];

  return (
    <GuardianLayout>
      {/* ── HIGH-RISK POPUP MODAL (ITEM 8) ── */}
      {highRiskPopupAlert && (
        <div className={styles.modalOverlay}>
          <div className={styles.modalCard}>
            <div className={styles.modalWarningIcon}>⚠</div>
            <div className={styles.modalHeader}>
              <span className={styles.modalBadge}>HIGH-RISK SECURITY ALERT</span>
              <h2 className={styles.modalTitle}>Suspicious Activity Detected</h2>
              <p className={styles.modalSub}>
                A potential cyber threat was flagged for your protected user <strong>{protectedName}</strong>.
              </p>
            </div>

            <div className={styles.modalDetailsBox}>
              <div className={styles.modalRow}>
                <span className={styles.modalLabel}>Threat Type</span>
                <span className={styles.modalVal}>{highRiskPopupAlert.type || 'Suspicious Interaction'}</span>
              </div>
              <div className={styles.modalRow}>
                <span className={styles.modalLabel}>Risk Level</span>
                <span className={styles.modalHighVal}>HIGH RISK</span>
              </div>
              <div className={styles.modalRow}>
                <span className={styles.modalLabel}>Detected At</span>
                <span className={styles.modalVal}>
                  {new Date(highRiskPopupAlert.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            </div>

            <p className={styles.modalAdvice}>
              💡 <strong>KAVACH Recommendation:</strong> Contact {protectedName} immediately and confirm they do not click unverified links, share OTPs, or transfer money.
            </p>

            <div className={styles.modalActions}>
              <button
                className={styles.modalViewBtn}
                onClick={() => {
                  setHighRiskPopupAlert(null);
                  navigate('/guardian/alerts');
                }}
              >
                VIEW FULL ALERT →
              </button>
              <button
                className={styles.modalDismissBtn}
                onClick={() => handleDismissAlert(highRiskPopupAlert.id)}
              >
                DISMISS
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MAIN CONTENT ── */}
      <main className={styles.main}>
        {/* ── HERO BANNER ── */}
        <section className={styles.heroSection}>
          <div>
            <span className={styles.sectionPill}>KAVACH GUARDIAN CONSOLE</span>
            <h1 className={styles.heroHeading}>
              GUARDIAN<br />
              PROTECTION HUB.
            </h1>
            <p className={styles.heroSubtitle}>
              Continuous security monitoring and telemetry for your protected family member.
            </p>
          </div>

          <div className={styles.quickNavCards}>
            <Link to="/guardian/protected-user" className={styles.quickCard}>
              <span className={styles.quickIcon}>👤</span>
              <div>
                <strong>Protected User</strong>
                <p>Privacy-safe profile & status</p>
              </div>
            </Link>
            <Link to="/guardian/alerts" className={styles.quickCard}>
              <span className={styles.quickIcon}>🔔</span>
              <div>
                <strong>Security Alerts</strong>
                <p>{alerts.length} active incident logs</p>
              </div>
            </Link>
            <Link to="/guardian/assistant" className={styles.quickCard}>
              <span className={styles.quickIcon}>🛡️</span>
              <div>
                <strong>AI Assistant</strong>
                <p>Cyber guidance & threat chat</p>
              </div>
            </Link>
          </div>
        </section>

        {/* ── DUAL HERO PANELS ── */}
        <section className={styles.dualGrid}>
          {/* Protected User Overview Card */}
          <div className={styles.userCard}>
            <div className={styles.cardTop}>
              <span className={styles.cardCategory}>PROTECTED FAMILY MEMBER</span>
              <span className={styles.protectStatusPill}>
                {isAttentionRequired ? '⚠ ATTENTION REQUIRED' : '✓ SECURE'}
              </span>
            </div>

            <div className={styles.userInfoRow}>
              <div className={styles.userAvatar}>
                {protectedName.charAt(0).toUpperCase()}
              </div>
              <div>
                <h2 className={styles.userName}>{protectedName}</h2>
                <span className={styles.userEmail}>{protectedEmail}</span>
              </div>
            </div>

            <div className={styles.metaGrid}>
              <div className={styles.metaItem}>
                <span className={styles.metaLabel}>PROTECTION STATUS</span>
                <span className={isAttentionRequired ? styles.metaValWarn : styles.metaValSafe}>
                  {isAttentionRequired ? 'HIGH RISK' : 'SAFE'}
                </span>
              </div>
              <div className={styles.metaItem}>
                <span className={styles.metaLabel}>SECURITY SCANS</span>
                <span className={styles.metaVal}>
                  {stats.threats_detected + stats.suspicious_messages + stats.suspicious_links + stats.suspicious_documents} Scans Logged
                </span>
              </div>
            </div>

            <div className={styles.cardFooter}>
              <Link to="/guardian/protected-user" className={styles.cardLink}>
                View Full Profile & Access Settings →
              </Link>
            </div>
          </div>

          {/* Overall Protection Status Card */}
          <div
            className={styles.statusPanel}
            style={isAttentionRequired ? { background: '#2a1215', borderColor: '#7f1d1d' } : {}}
          >
            <div className={styles.cardTop}>
              <span className={styles.cardCategory}>SYSTEM DEFENSE STATUS</span>
              <span className={styles.livePulseTag}>LIVE TELEMETRY</span>
            </div>

            <div className={styles.statusHero}>
              <div
                className={styles.statusIndicatorCircle}
                style={isAttentionRequired ? { background: '#ef4444', boxShadow: '0 0 16px rgba(239,68,68,0.5)' } : {}}
              />
              <div>
                <h2 className={styles.statusHeadline}>
                  {isAttentionRequired ? 'ATTENTION REQUIRED' : 'PROTECTION ACTIVE'}
                </h2>
                <p className={styles.statusDesc}>
                  {isAttentionRequired
                    ? `${stats.threats_detected} scam threat(s) flagged for your protected user.`
                    : 'All communication channels, links, and uploaded files are verified safe.'}
                </p>
              </div>
            </div>

            <div className={styles.protectionModulesRow}>
              <span className={styles.modBadge}>AI Scam Filter</span>
              <span className={styles.modBadge}>Phishing Detection</span>
              <span className={styles.modBadge}>Malware URL Shield</span>
            </div>
          </div>
        </section>

        {/* ── SECURITY METRICS TELEMETRY ── */}
        <section className={styles.metricsSection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>SECURITY INCIDENT TELEMETRY</h2>
            <span className={styles.subtext}>Verified PostgreSQL database statistics</span>
          </div>

          <div className={styles.metricsGrid}>
            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>THREATS DETECTED</span>
              <span className={styles.metricNum} style={stats.threats_detected > 0 ? { color: '#ef4444' } : {}}>
                {stats.threats_detected}
              </span>
              <span className={styles.metricSub}>Critical Scam Alerts</span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>SUSPICIOUS MESSAGES</span>
              <span className={styles.metricNum}>{stats.suspicious_messages}</span>
              <span className={styles.metricSub}>Urgency & OTP Flags</span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>SUSPICIOUS LINKS</span>
              <span className={styles.metricNum}>{stats.suspicious_links}</span>
              <span className={styles.metricSub}>Deceptive Domains</span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>SUSPICIOUS DOCUMENTS</span>
              <span className={styles.metricNum}>{stats.suspicious_documents}</span>
              <span className={styles.metricSub}>Malicious Files</span>
            </div>
          </div>
        </section>

        {/* ── RECENT ALERTS SECTION ── */}
        <section className={styles.alertsSection}>
          <div className={styles.sectionHeader}>
            <div>
              <h2 className={styles.sectionTitle}>RECENT GUARDIAN SECURITY ALERTS</h2>
              <span className={styles.subtext}>Privacy-safe incident summaries</span>
            </div>
            <Link to="/guardian/alerts" className={styles.viewAllLink}>
              VIEW ALL ALERTS ({alerts.length}) →
            </Link>
          </div>

          {alerts.length === 0 ? (
            <div className={styles.emptyAlerts}>
              <span style={{ fontSize: '28px' }}>🛡️</span>
              <strong>No Active High-Risk Alerts</strong>
              <p>Your protected user currently has zero flagged security incidents.</p>
            </div>
          ) : (
            <div className={styles.alertList}>
              {alerts.slice(0, 4).map((alt) => (
                <div key={alt.id} className={styles.alertRow}>
                  <div className={styles.alertMain}>
                    <div className={styles.alertTopLine}>
                      <span className={styles.alertTitle}>{alt.title}</span>
                      <span className={alt.severity === 'HIGH' ? styles.badgeHigh : styles.badgeMed}>
                        {alt.severity}
                      </span>
                    </div>
                    <span className={styles.alertAction}>
                      ⚡ Recommended Action: {alt.recommended_action}
                    </span>
                    <span className={styles.alertTimestamp}>
                      Logged: {new Date(alt.time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── CYBER INCIDENT REPORTS SECTION ── */}
        <section className={styles.reportsSection}>
          <div className={styles.sectionHeader}>
            <div>
              <h2 className={styles.sectionTitle}>CYBER INCIDENT REPORTS</h2>
              <span className={styles.subtext}>
                Automatically generated when KAVACH detects a high-risk security incident
              </span>
            </div>
            <button
              className={styles.refreshBtn}
              onClick={loadReports}
              disabled={reportsLoading}
            >
              {reportsLoading ? '↻ Loading…' : '↻ Refresh'}
            </button>
          </div>

          {reportsLoading ? (
            <div className={styles.reportSkeletonList}>
              {[1, 2].map((i) => (
                <div key={i} className={styles.reportSkeleton} />
              ))}
            </div>
          ) : reportsError ? (
            <div className={styles.reportsError}>
              <span>⚠</span>
              <p>{reportsError}</p>
              <button className={styles.retryBtn} onClick={loadReports}>Try Again</button>
            </div>
          ) : reports.length === 0 ? (
            <div className={styles.reportsEmpty}>
              <span style={{ fontSize: '28px' }}>🛡️</span>
              <strong>No Cyber Incident Reports Available</strong>
              <p>Reports are automatically generated when KAVACH detects a high-risk security incident.</p>
            </div>
          ) : (
            <div className={styles.reportList}>
              {reports.map((rep) => (
                <div key={rep.report_id} className={styles.reportCard}>
                  <div className={styles.reportCardHeader}>
                    <div className={styles.reportCardLeft}>
                      <span className={styles.reportId}>{rep.report_id}</span>
                      <span className={styles.reportIdLabel}>REPORT ID</span>
                    </div>
                    <span className={styles.reportRiskBadge}>
                      HIGH RISK
                    </span>
                  </div>

                  <div className={styles.reportCardBody}>
                    <div className={styles.reportMeta}>
                      <div className={styles.reportMetaItem}>
                        <span className={styles.reportMetaLabel}>INCIDENT TYPE</span>
                        <span className={styles.reportMetaVal}>
                          {getIncidentTypeLabel(rep.incident_type)}
                        </span>
                      </div>
                      <div className={styles.reportMetaItem}>
                        <span className={styles.reportMetaLabel}>RISK SCORE</span>
                        <span className={styles.reportMetaVal}>{rep.risk_score}/100</span>
                      </div>
                      <div className={styles.reportMetaItem}>
                        <span className={styles.reportMetaLabel}>DETECTED</span>
                        <span className={styles.reportMetaVal}>
                          {new Date(rep.detected_at).toLocaleString([], {
                            month: 'short', day: 'numeric', year: 'numeric',
                            hour: '2-digit', minute: '2-digit'
                          })}
                        </span>
                      </div>
                      <div className={styles.reportMetaItem}>
                        <span className={styles.reportMetaLabel}>STATUS</span>
                        <span className={styles.reportStatusPill}>{rep.status}</span>
                      </div>
                    </div>

                    <p className={styles.reportSummary}>
                      {rep.summary?.substring(0, 180)}{rep.summary?.length > 180 ? '…' : ''}
                    </p>
                  </div>

                  <div className={styles.reportDisclaimer}>
                    ℹ This is a documentation draft generated by KAVACH and is not an official complaint filing.
                  </div>

                  <div className={styles.reportCardActions}>
                    <button
                      className={styles.reportViewBtn}
                      onClick={() => handleViewReport(rep.report_id)}
                      disabled={reportDetailLoading}
                    >
                      {reportDetailLoading ? 'Loading…' : 'View Report'}
                    </button>
                    <button
                      className={styles.reportDownloadBtn}
                      onClick={() => handleDownloadPdf(rep.report_id)}
                      disabled={downloadingId === rep.report_id}
                    >
                      {downloadingId === rep.report_id ? '⟳ Downloading…' : '⬇ Download PDF'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── EMERGENCY ACTIONS GUIDANCE ── */}
        <section className={styles.emergencyCard}>
          <div className={styles.emergencyHeader}>
            <span className={styles.emergencyBadge}>GUARDIAN EMERGENCY PROTOCOL</span>
            <h2 className={styles.emergencyTitle}>Steps If You Suspect An Active Scam</h2>
          </div>

          <div className={styles.stepsGrid}>
            <div className={styles.stepBox}>
              <span className={styles.stepCount}>01</span>
              <strong>Prevent Payments & OTPs</strong>
              <p>Instruct {protectedName} never to approve sudden bank transfers or share SMS OTPs.</p>
            </div>
            <div className={styles.stepBox}>
              <span className={styles.stepCount}>02</span>
              <strong>Verify Out-of-Band</strong>
              <p>Call the protected user or the official bank branch directly to verify claims.</p>
            </div>
            <div className={styles.stepBox}>
              <span className={styles.stepCount}>03</span>
              <strong>Check Detection Log</strong>
              <p>Use the KAVACH Guardian Activity page to review threat indicators in real-time.</p>
            </div>
          </div>
        </section>
      </main>

      {/* ── REPORT DETAIL MODAL ── */}
      {selectedReport && (
        <div className={styles.modalOverlay} onClick={() => setSelectedReport(null)}>
          <div
            className={styles.reportModal}
            onClick={(e) => e.stopPropagation()}
          >
            <div className={styles.reportModalHeader}>
              <div>
                <span className={styles.reportModalBadge}>CYBER SECURITY INCIDENT REPORT</span>
                <h2 className={styles.reportModalTitle}>{selectedReport.title}</h2>
              </div>
              <button
                className={styles.reportModalClose}
                onClick={() => setSelectedReport(null)}
              >
                ✕
              </button>
            </div>

            <div className={styles.reportModalGrid}>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Report ID</span>
                <span className={styles.reportModalVal}>{selectedReport.report_id}</span>
              </div>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Incident Type</span>
                <span className={styles.reportModalVal}>
                  {getIncidentTypeLabel(selectedReport.incident_type)}
                </span>
              </div>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Risk Level</span>
                <span className={styles.modalHighVal}>{selectedReport.risk_level}</span>
              </div>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Risk Score</span>
                <span className={styles.reportModalVal}>{selectedReport.risk_score}/100</span>
              </div>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Detection Time</span>
                <span className={styles.reportModalVal}>
                  {new Date(selectedReport.detected_at).toLocaleString()}
                </span>
              </div>
              <div className={styles.reportModalItem}>
                <span className={styles.reportModalLabel}>Status</span>
                <span className={styles.reportStatusPill}>{selectedReport.status}</span>
              </div>
            </div>

            <div className={styles.reportModalSection}>
              <span className={styles.reportModalSectionTitle}>Incident Summary</span>
              <p className={styles.reportModalText}>{selectedReport.summary}</p>
            </div>

            {selectedReport.sanitized_evidence?.detected_indicators?.length > 0 && (
              <div className={styles.reportModalSection}>
                <span className={styles.reportModalSectionTitle}>Detected Threat Indicators</span>
                <ul className={styles.indicatorList}>
                  {selectedReport.sanitized_evidence.detected_indicators.slice(0, 6).map((ind, i) => (
                    <li key={i} className={styles.indicatorItem}>⚠ {ind}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className={styles.reportModalSection}>
              <span className={styles.reportModalSectionTitle}>Recommended Safety Actions</span>
              <div className={styles.reportSafetyBox}>
                <p>1. Do NOT click links, QR codes, or respond to this incident.</p>
                <p>2. Contact {protectedName} immediately to verify they have not made any payments or shared OTPs.</p>
                <p>3. Use this report as a reference when filing an official complaint with law enforcement if needed.</p>
              </div>
            </div>

            <div className={styles.reportModalDisclaimer}>
              ℹ This report is a documentation draft generated by KAVACH and is not an official complaint filing with any law-enforcement authority.
            </div>

            <div className={styles.reportModalActions}>
              <button
                className={styles.reportDownloadBtn}
                onClick={() => {
                  handleDownloadPdf(selectedReport.report_id);
                  setSelectedReport(null);
                }}
              >
                ⬇ Download Privacy-Sanitized PDF
              </button>
              <button
                className={styles.modalDismissBtn}
                onClick={() => setSelectedReport(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </GuardianLayout>
  );
}
