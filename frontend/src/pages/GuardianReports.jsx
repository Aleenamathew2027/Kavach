import { useState, useEffect, useCallback } from 'react';
import { api, getToken } from '../services/api';
import GuardianLayout from '../components/GuardianLayout';
import ThreatInfrastructureMap from '../components/ThreatInfrastructureMap';
import styles from './GuardianReports.module.css';

const INCIDENT_LABELS = {
  SCAM_MESSAGE: 'Scam Message',
  PHISHING_LINK: 'Phishing Link',
  SUSPICIOUS_DOCUMENT: 'Suspicious Document',
  SUSPICIOUS_QR: 'QR Code Threat',
  MULTI_SIGNAL_SCAM: 'Multi-Signal Scam',
};

function getIncidentTypeLabel(type) {
  return INCIDENT_LABELS[type] || type;
}

/**
 * GuardianReports — dedicated page for viewing and downloading
 * privacy-sanitized cyber incident reports.
 */
export default function GuardianReports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);
  const [showGuardianMap, setShowGuardianMap] = useState(false);

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getGuardianReports();
      setReports(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Error loading guardian reports:', err);
      setError('Unable to load cyber incident reports. Please try again.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleViewReport = async (reportId) => {
    setDetailLoading(true);
    try {
      const detail = await api.getGuardianReportDetail(reportId);
      setSelectedReport(detail);
    } catch (err) {
      console.error('Error fetching report detail:', err);
      alert('Unable to load report details. Please try again.');
    } finally {
      setDetailLoading(false);
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

  return (
    <GuardianLayout>
      <div className={styles.page}>
        {/* Page Header */}
        <div className={styles.pageHeader}>
          <div>
            <span className={styles.eyebrow}>DOCUMENTATION ARCHIVE</span>
            <h1 className={styles.title}>CYBER INCIDENT REPORTS</h1>
            <p className={styles.subtitle}>
              Automatically generated when KAVACH detects a high-risk security incident for your protected user.
            </p>
          </div>
          <button
            className={styles.refreshBtn}
            onClick={loadReports}
            disabled={loading}
          >
            {loading ? '↻ Loading…' : '↻ Refresh Reports'}
          </button>
        </div>

        {/* Privacy Notice */}
        <div className={styles.privacyBanner}>
          <span className={styles.privacyIcon}>🔒</span>
          <p>
            All reports are privacy-sanitized. Personal message content, passwords, and private files
            are never included. Reports are documentation drafts only — not official complaint filings.
          </p>
        </div>

        {/* Reports List */}
        {loading ? (
          <div className={styles.skeletonList}>
            {[1, 2, 3].map((i) => (
              <div key={i} className={styles.skeleton} />
            ))}
          </div>
        ) : error ? (
          <div className={styles.errorState}>
            <span>⚠</span>
            <p>{error}</p>
            <button className={styles.retryBtn} onClick={loadReports}>
              Try Again
            </button>
          </div>
        ) : reports.length === 0 ? (
          <div className={styles.emptyState}>
            <span className={styles.emptyIcon}>🛡️</span>
            <h3>No Cyber Incident Reports Available</h3>
            <p>
              Reports are automatically generated when KAVACH detects a high-risk security incident.
              Your protected user currently has no flagged incidents.
            </p>
          </div>
        ) : (
          <div className={styles.reportGrid}>
            {reports.map((rep) => (
              <div key={rep.report_id} className={styles.reportCard}>
                {/* Card Header */}
                <div className={styles.cardHeader}>
                  <div className={styles.cardHeaderLeft}>
                    <span className={styles.reportIdLabel}>REPORT ID</span>
                    <span className={styles.reportId}>{rep.report_id}</span>
                  </div>
                  <span className={styles.riskBadge}>HIGH RISK</span>
                </div>

                {/* Card Body */}
                <div className={styles.cardBody}>
                  <div className={styles.metaGrid}>
                    <div className={styles.metaItem}>
                      <span className={styles.metaLabel}>INCIDENT TYPE</span>
                      <span className={styles.metaVal}>
                        {getIncidentTypeLabel(rep.incident_type)}
                      </span>
                    </div>
                    <div className={styles.metaItem}>
                      <span className={styles.metaLabel}>RISK SCORE</span>
                      <span className={styles.metaVal}>{rep.risk_score}/100</span>
                    </div>
                    <div className={styles.metaItem}>
                      <span className={styles.metaLabel}>DETECTED</span>
                      <span className={styles.metaVal}>
                        {new Date(rep.detected_at).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    </div>
                    <div className={styles.metaItem}>
                      <span className={styles.metaLabel}>STATUS</span>
                      <span className={styles.statusPill}>{rep.status}</span>
                    </div>
                  </div>

                  <p className={styles.summary}>
                    {rep.summary?.substring(0, 180)}
                    {rep.summary?.length > 180 ? '…' : ''}
                  </p>
                </div>

                {/* Disclaimer */}
                <div className={styles.disclaimer}>
                  ℹ This is a documentation draft generated by KAVACH and is not an official complaint filing.
                </div>

                {/* Actions */}
                <div className={styles.cardActions}>
                  <button
                    className={styles.viewBtn}
                    onClick={() => handleViewReport(rep.report_id)}
                    disabled={detailLoading}
                  >
                    {detailLoading ? 'Loading…' : 'View Report'}
                  </button>
                  <button
                    className={styles.downloadBtn}
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

        {/* Report Detail Modal */}
        {selectedReport && (
          <div className={styles.modalOverlay} onClick={() => setSelectedReport(null)}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
              <div className={styles.modalHeader}>
                <div>
                  <span className={styles.modalBadge}>CYBER SECURITY INCIDENT REPORT</span>
                  <h2 className={styles.modalTitle}>{selectedReport.title}</h2>
                </div>
                <button
                  className={styles.modalClose}
                  onClick={() => setSelectedReport(null)}
                >
                  ✕
                </button>
              </div>

              <div className={styles.modalGrid}>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Report ID</span>
                  <span className={styles.modalVal}>{selectedReport.report_id}</span>
                </div>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Incident Type</span>
                  <span className={styles.modalVal}>
                    {getIncidentTypeLabel(selectedReport.incident_type)}
                  </span>
                </div>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Risk Level</span>
                  <span className={styles.modalHighVal}>{selectedReport.risk_level}</span>
                </div>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Risk Score</span>
                  <span className={styles.modalVal}>{selectedReport.risk_score}/100</span>
                </div>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Detection Time</span>
                  <span className={styles.modalVal}>
                    {new Date(selectedReport.detected_at).toLocaleString()}
                  </span>
                </div>
                <div className={styles.modalItem}>
                  <span className={styles.modalLabel}>Status</span>
                  <span className={styles.modalStatusPill}>{selectedReport.status}</span>
                </div>
              </div>

              <div className={styles.modalSection}>
                <span className={styles.modalSectionTitle}>Incident Summary</span>
                <p className={styles.modalText}>{selectedReport.summary}</p>
              </div>

              {selectedReport.sanitized_evidence?.detected_indicators?.length > 0 && (
                <div className={styles.modalSection}>
                  <span className={styles.modalSectionTitle}>Detected Threat Indicators</span>
                  <ul className={styles.indicatorList}>
                    {selectedReport.sanitized_evidence.detected_indicators
                      .slice(0, 6)
                      .map((ind, i) => (
                        <li key={i} className={styles.indicatorItem}>
                          ⚠ {ind}
                        </li>
                      ))}
                  </ul>
                </div>
              )}

              {/* ── THREAT INFRASTRUCTURE LOCATION (PHASE 18C) ── */}
              {selectedReport.threat_infrastructure?.available && (
                <div className={styles.modalSection}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '8px',
                      flexWrap: 'wrap',
                      gap: '8px',
                    }}
                  >
                    <span className={styles.modalSectionTitle}>Threat Infrastructure Location</span>
                    <button
                      type="button"
                      onClick={() => setShowGuardianMap(!showGuardianMap)}
                      style={{
                        background: showGuardianMap ? 'rgba(0, 137, 123, 0.3)' : 'rgba(255, 255, 255, 0.08)',
                        color: '#5eead4',
                        border: '1px solid rgba(94, 234, 212, 0.3)',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      {showGuardianMap ? '▲ Hide Map' : '🗺 View on Interactive Map'}
                    </button>
                  </div>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                      gap: '10px',
                      background: 'rgba(6, 35, 38, 0.6)',
                      border: '1px solid rgba(94, 234, 212, 0.2)',
                      borderRadius: '6px',
                      padding: '12px',
                      fontSize: '12px',
                    }}
                  >
                    <div>
                      <span style={{ color: '#80cbc4', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Location</span>
                      <strong style={{ color: '#fcfbf7' }}>
                        {[selectedReport.threat_infrastructure.city, selectedReport.threat_infrastructure.region, selectedReport.threat_infrastructure.country].filter(Boolean).join(', ') || 'N/A'}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: '#80cbc4', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Public IP</span>
                      <strong style={{ color: '#fcfbf7' }}>{selectedReport.threat_infrastructure.ip_address || 'Unresolved'}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#80cbc4', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Network Provider</span>
                      <strong style={{ color: '#fcfbf7' }}>{selectedReport.threat_infrastructure.isp || selectedReport.threat_infrastructure.organization || 'N/A'}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#80cbc4', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Autonomous System</span>
                      <strong style={{ color: '#fcfbf7' }}>{selectedReport.threat_infrastructure.asn || 'N/A'}</strong>
                    </div>
                    {selectedReport.threat_infrastructure.domain && (
                      <div>
                        <span style={{ color: '#80cbc4', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Domain</span>
                        <strong style={{ color: '#fcfbf7' }}>{selectedReport.threat_infrastructure.domain}</strong>
                      </div>
                    )}
                  </div>

                  {showGuardianMap && (
                    <div style={{ marginTop: '12px' }}>
                      <ThreatInfrastructureMap
                        location={selectedReport.threat_infrastructure}
                        height="340px"
                        theme="guardian"
                      />
                    </div>
                  )}

                  <div
                    style={{
                      marginTop: '8px',
                      fontSize: '10.5px',
                      color: '#80cbc4',
                      lineHeight: 1.4,
                    }}
                  >
                    ℹ Threat infrastructure location is approximate and is derived from public network information associated with the suspicious destination. It may represent hosting infrastructure, CDN points of presence, VPN/proxy infrastructure, or ISP routing infrastructure and does not identify the physical location of an individual.
                  </div>
                </div>
              )}

              <div className={styles.modalSection}>
                <span className={styles.modalSectionTitle}>Recommended Safety Actions</span>
                <div className={styles.safetyBox}>
                  <p>1. Do NOT click links, QR codes, or respond to this incident.</p>
                  <p>
                    2. Contact your protected user immediately to verify they have not made any
                    payments or shared OTPs.
                  </p>
                  <p>
                    3. Use this report as a reference when filing an official complaint with law
                    enforcement if needed.
                  </p>
                </div>
              </div>

              <div className={styles.modalDisclaimer}>
                ℹ This report is a documentation draft generated by KAVACH and is not an official
                complaint filing with any law-enforcement authority.
              </div>

              <div className={styles.modalActions}>
                <button
                  className={styles.downloadBtn}
                  onClick={() => {
                    handleDownloadPdf(selectedReport.report_id);
                    setSelectedReport(null);
                  }}
                >
                  ⬇ Download Privacy-Sanitized PDF
                </button>
                <button
                  className={styles.modalCloseBtn}
                  onClick={() => setSelectedReport(null)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </GuardianLayout>
  );
}
