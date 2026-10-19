import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api, getToken } from '../services/api';
import UserLayout from '../components/UserLayout';
import styles from './UserDashboard.module.css';

export default function UserReports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);

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
