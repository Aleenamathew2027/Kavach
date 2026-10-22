import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api, getToken } from '../services/api';
import UserLayout from '../components/UserLayout';
import ThreatInfrastructureMap from '../components/ThreatInfrastructureMap';
import styles from './UserDashboard.module.css';

export default function UserReports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [expandedMapId, setExpandedMapId] = useState(null);

  useEffect(() => {
    async function loadReports() {
      setLoading(true);
      try {
        const data = await api.getUserReports();
        if (Array.isArray(data)) setReports(data);
      } catch (err) {
        console.error('Failed to load incident reports:', err);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const handleDownloadPdf = async (reportId) => {
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
      alert('Unable to download the incident report. Please try again.');
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <UserLayout
      eyebrow="CYBERCRIME EVIDENCE &amp; AUDIT TRAIL"
      title="CYBER INCIDENT REPORTS"
      subtitle="Formal security incident dossiers and police complaint drafts generated automatically for high-risk threats."
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--kavach-shellstone)' }}>
            Loading incident records…
          </div>
        ) : reports.length === 0 ? (
          <div
            style={{
              background: 'rgba(26, 46, 94, 0.4)',
              border: '1px solid rgba(217, 203, 194, 0.12)',
              borderRadius: '6px',
              padding: '48px 32px',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <div style={{ fontSize: '38px' }}>🛡️</div>
            <h3 style={{ fontFamily: 'Space Grotesk', fontSize: '18px', color: 'var(--kavach-swan-wing)', margin: 0 }}>
              No High-Risk Cyber Incident Reports
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--kavach-shellstone)', maxWidth: '480px', margin: 0, lineHeight: 1.6 }}>
              When KAVACH intercepts a critical threat (such as an active phishing website, banking fraud message, or malicious invoice), an official complaint draft and PDF report will be prepared here automatically.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {reports.map((rep) => (
              <div key={rep.report_id} className={styles.reportCard}>
                <div className={styles.reportCardHeader}>
                  <div>
                    <span className={styles.reportBadge}>HIGH RISK INCIDENT DETECTED</span>
                    <div className={styles.reportIdText}>Report ID: {rep.report_id}</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={styles.reportTypeLabel}>
                      {rep.incident_type?.replace(/_/g, ' ')}
                    </span>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        color: 'var(--kavach-quicksand)',
                        background: 'rgba(224, 197, 143, 0.12)',
                        border: '1px solid rgba(224, 197, 143, 0.3)',
                        padding: '3px 8px',
                        borderRadius: '2px',
                      }}
                    >
                      DRAFTED
                    </span>
                  </div>
                </div>

                <p className={styles.reportSummaryText}>
                  A Cyber Security Incident Report / Complaint Draft has been automatically compiled. This document records digital evidence and threat telemetry suitable for filing with national cybercrime authorities (e.g. 1930 / cybercrime.gov.in) or your banking institution.
                </p>

                {/* ── THREAT INFRASTRUCTURE LOCATION (PHASE 18C) ── */}
                {rep.threat_infrastructure?.available ? (
                  <div
                    style={{
                      background: 'rgba(11, 24, 48, 0.45)',
                      border: '1px solid rgba(220, 38, 38, 0.3)',
                      borderRadius: '6px',
                      padding: '16px',
                      marginTop: '12px',
                      marginBottom: '12px',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        flexWrap: 'wrap',
                        gap: '8px',
                        marginBottom: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '15px' }}>🌐</span>
                        <span
                          style={{
                            fontFamily: 'Space Grotesk, sans-serif',
                            fontSize: '12px',
                            fontWeight: 700,
                            color: '#fca5a5',
                            letterSpacing: '0.06em',
                            textTransform: 'uppercase',
                          }}
                        >
                          THREAT INFRASTRUCTURE LOCATION
                        </span>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '3px',
                            background: 'rgba(239, 68, 68, 0.2)',
                            color: '#f87171',
                            border: '1px solid rgba(239, 68, 68, 0.35)',
                          }}
                        >
                          APPROXIMATE IP INFRASTRUCTURE
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => setExpandedMapId(expandedMapId === rep.report_id ? null : rep.report_id)}
                        style={{
                          background: expandedMapId === rep.report_id ? 'rgba(220, 38, 38, 0.3)' : 'rgba(255, 255, 255, 0.08)',
                          color: '#f1f5f9',
                          border: '1px solid rgba(255, 255, 255, 0.2)',
                          padding: '5px 12px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                      >
                        {expandedMapId === rep.report_id ? '▲ Hide Map' : '🗺 View on Interactive Map'}
                      </button>
                    </div>

                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                        gap: '10px',
                        fontSize: '12px',
                      }}
                    >
                      <div>
                        <span style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Location</span>
                        <strong style={{ color: '#f1f5f9' }}>
                          {[rep.threat_infrastructure.city, rep.threat_infrastructure.region, rep.threat_infrastructure.country].filter(Boolean).join(', ') || 'N/A'}
                        </strong>
                      </div>
                      <div>
                        <span style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Public IP</span>
                        <strong style={{ color: '#f1f5f9' }}>{rep.threat_infrastructure.ip_address || 'Unresolved'}</strong>
                      </div>
                      <div>
                        <span style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Network Provider</span>
                        <strong style={{ color: '#f1f5f9' }}>{rep.threat_infrastructure.isp || rep.threat_infrastructure.organization || 'N/A'}</strong>
                      </div>
                      <div>
                        <span style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Autonomous System</span>
                        <strong style={{ color: '#f1f5f9' }}>{rep.threat_infrastructure.asn || 'N/A'}</strong>
                      </div>
                      {rep.threat_infrastructure.domain && (
                        <div>
                          <span style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', display: 'block' }}>Domain</span>
                          <strong style={{ color: '#f1f5f9' }}>{rep.threat_infrastructure.domain}</strong>
                        </div>
                      )}
                    </div>

                    {expandedMapId === rep.report_id && (
                      <div style={{ marginTop: '14px' }}>
                        <ThreatInfrastructureMap location={rep.threat_infrastructure} height="360px" />
                      </div>
                    )}

                    <div
                      style={{
                        marginTop: '10px',
                        fontSize: '10.5px',
                        color: '#94a3b8',
                        lineHeight: 1.4,
                        borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                        paddingTop: '6px',
                      }}
                    >
                      ℹ Threat infrastructure location is approximate and is derived from public network information associated with the suspicious destination. It may represent hosting infrastructure, CDN points of presence, VPN/proxy infrastructure, or ISP routing infrastructure and does not identify the physical location of an individual.
                    </div>
                  </div>
                ) : (
                  <div
                    style={{
                      background: 'rgba(255, 255, 255, 0.03)',
                      borderRadius: '4px',
                      padding: '8px 12px',
                      marginTop: '8px',
                      marginBottom: '8px',
                      fontSize: '11px',
                      color: 'var(--kavach-shellstone)',
                    }}
                  >
                    ℹ Threat infrastructure location was not available for this incident.
                  </div>
                )}

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '12px',
                    paddingTop: '12px',
                    borderTop: '1px solid rgba(217, 203, 194, 0.1)',
                  }}
                >
                  <span style={{ fontSize: '11.5px', color: 'var(--kavach-shellstone)' }}>
                    Generated: {new Date(rep.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}
                  </span>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <Link to="/user/alerts" className={styles.reportViewAlertsBtn}>
                      View Correlated Alerts →
                    </Link>
                    <button
                      type="button"
                      className={styles.reportDownloadBtn}
                      onClick={() => handleDownloadPdf(rep.report_id)}
                      disabled={downloadingId === rep.report_id}
                    >
                      {downloadingId === rep.report_id ? '⟳ Downloading PDF…' : '⬇ Download PDF Report'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </UserLayout>
  );
}
