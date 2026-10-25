import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, clearAuth } from '../services/api';
import { guardianChatService } from '../services/guardianChatService';
import GuardianLayout from '../components/GuardianLayout';
import styles from './GuardianSettings.module.css';

export default function GuardianSettings() {
  const navigate = useNavigate();
  const [guardianData, setGuardianData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saveMsg, setSaveMsg] = useState('');
  const [testSmsStatus, setTestSmsStatus] = useState('');
  const [sendingTest, setSendingTest] = useState(false);

  // In-app alert preferences
  const [highRiskAlertsOnly, setHighRiskAlertsOnly] = useState(false);
  const [browserNotifications, setBrowserNotifications] = useState(true);

  // SMS Notification settings from API
  const [guardianPhone, setGuardianPhone] = useState('');
  const [smsHighRisk, setSmsHighRisk] = useState(true);
  const [smsCritical, setSmsCritical] = useState(true);
  const [smsSuspicious, setSmsSuspicious] = useState(false);
  const [smsConfigured, setSmsConfigured] = useState(false);
  const [smsProviderName, setSmsProviderName] = useState('mock');

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [dashData, smsSettings] = await Promise.allSettled([
          api.getGuardianDashboard(),
          guardianChatService.getSettings(),
        ]);

        if (dashData.status === 'fulfilled') {
          setGuardianData(dashData.value);
        }

        if (smsSettings.status === 'fulfilled' && smsSettings.value) {
          const s = smsSettings.value;
          setGuardianPhone(s.guardian_phone || '');
          setSmsHighRisk(s.sms_high_risk ?? true);
          setSmsCritical(s.sms_critical ?? true);
          setSmsSuspicious(s.sms_suspicious ?? false);
          setSmsConfigured(Boolean(s.is_sms_configured));
          setSmsProviderName(s.sms_provider || 'mock');
        }
      } catch (err) {
        console.error('Error loading guardian settings:', err);
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

  const handleSave = async (e) => {
    e.preventDefault();
    setSaveMsg('');
    try {
      await guardianChatService.updateSettings({
        guardian_phone: guardianPhone,
        sms_high_risk: smsHighRisk,
        sms_critical: smsCritical,
        sms_suspicious: smsSuspicious,
      });
      setSaveMsg('Preferences and SMS settings saved successfully.');
    } catch (err) {
      console.error('Error saving settings:', err);
      setSaveMsg('Preferences saved for session (SMS backend sync error).');
    }
    setTimeout(() => setSaveMsg(''), 4000);
  };

  const handleSendTestSMS = async () => {
    setSendingTest(true);
    setTestSmsStatus('');
    try {
      const res = await guardianChatService.sendTestSMS(guardianPhone);
      if (res.status === 'SENT') {
        setTestSmsStatus(`✓ Test SMS dispatched successfully (${res.provider || 'Provider'}). Note: ${res.note || 'Delivered'}`);
      } else {
        setTestSmsStatus(`⚠ ${res.note || 'SMS notifications are not configured.'}`);
      }
    } catch (err) {
      console.error('Test SMS error:', err);
      setTestSmsStatus(err.message || 'SMS notifications are not configured.');
    } finally {
      setSendingTest(false);
      setTimeout(() => setTestSmsStatus(''), 6000);
    }
  };

  const protectedUser = guardianData?.guarded_user || { full_name: 'Protected User', email: '—' };
  const authUntil = guardianData?.authorized_until
    ? new Date(guardianData.authorized_until).toLocaleString([], {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '24-Hour Active Session';

  return (
    <GuardianLayout>
      <div className={styles.page}>
        <main className={styles.main}>
          <div className={styles.header}>
            <span className={styles.sectionPill}>GUARDIAN PREFERENCES</span>
            <h1 className={styles.title}>GUARDIAN SETTINGS</h1>
            <p className={styles.subtitle}>
              Manage your guardian authorization session, alert thresholds, SMS dispatch policies, and security preferences.
            </p>
          </div>

          {saveMsg && <div className={styles.bannerSuccess}>✓ {saveMsg}</div>}
          {testSmsStatus && <div className={styles.bannerSuccess}>{testSmsStatus}</div>}

          {/* ── AUTHORIZATION DETAILS ── */}
          <section className={styles.card}>
            <h2 className={styles.cardTitle}>GUARDIAN AUTHORIZATION STATUS</h2>
            <div className={styles.infoGrid}>
              <div className={styles.infoBox}>
                <span className={styles.infoLabel}>PROTECTED USER</span>
                <span className={styles.infoVal}>
                  {protectedUser.full_name} ({protectedUser.email})
                </span>
              </div>
              <div className={styles.infoBox}>
                <span className={styles.infoLabel}>AUTHORIZATION ACCESS</span>
                <span className={styles.infoValSuccess}>ACTIVE & VERIFIED</span>
              </div>
              <div className={styles.infoBox}>
                <span className={styles.infoLabel}>PASS VALID UNTIL</span>
                <span className={styles.infoVal}>{authUntil}</span>
              </div>
              <div className={styles.infoBox}>
                <span className={styles.infoLabel}>SECURITY CLEARANCE</span>
                <span className={styles.infoVal}>Real-time Threat Interceptions</span>
              </div>
            </div>
          </section>

          {/* ── SMS NOTIFICATION SETTINGS ── */}
          <section className={styles.card}>
            <h2 className={styles.cardTitle}>EMERGENCY SMS NOTIFICATIONS</h2>
            
            {smsConfigured ? (
              <span className={`${styles.providerBadge} ${styles.providerConfigured}`}>
                SMS GATEWAY ACTIVE: {smsProviderName.toUpperCase()}
              </span>
            ) : (
              <span className={`${styles.providerBadge} ${styles.providerUnconfigured}`}>
                SMS notifications are not configured (Sandbox Mock Provider)
              </span>
            )}

            <form onSubmit={handleSave} className={styles.settingsForm}>
              <div className={styles.phoneInputGroup}>
                <label className={styles.infoLabel} htmlFor="guardianPhone">
                  GUARDIAN MOBILE PHONE NUMBER
                </label>
                <input
                  id="guardianPhone"
                  type="tel"
                  className={styles.phoneInput}
                  placeholder="+91 98765 43210 or +1 234 567 8900"
                  value={guardianPhone}
                  onChange={(e) => setGuardianPhone(e.target.value)}
                />
                <span style={{ fontSize: '11px', color: '#6F807B' }}>
                  Emergency SMS alerts for critical scam attempts will be sent to this number.
                </span>
              </div>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={smsCritical}
                  onChange={(e) => setSmsCritical(e.target.checked)}
                />
                <div>
                  <strong>Critical Threat SMS Alerts (Recommended)</strong>
                  <p>Immediate SMS dispatch when active OTP/credential theft or confirmed high-loss fraud occurs.</p>
                </div>
              </label>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={smsHighRisk}
                  onChange={(e) => setSmsHighRisk(e.target.checked)}
                />
                <div>
                  <strong>High-Risk Threat SMS Alerts</strong>
                  <p>Receive SMS alerts when verified phishing links, malicious APKs, or vishing calls are detected.</p>
                </div>
              </label>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={smsSuspicious}
                  onChange={(e) => setSmsSuspicious(e.target.checked)}
                />
                <div>
                  <strong>Suspicious Telemetry SMS (Optional)</strong>
                  <p>Dispatch SMS for lower-severity suspicious telemetry (may increase SMS volume).</p>
                </div>
              </label>

              <div className={styles.actionRow}>
                <button type="submit" className={styles.saveBtn}>
                  SAVE PREFERENCES
                </button>

                <button
                  type="button"
                  onClick={handleSendTestSMS}
                  className={styles.testSmsBtn}
                  disabled={sendingTest}
                >
                  {sendingTest ? 'DISPATCHING TEST…' : 'SEND TEST SMS'}
                </button>
              </div>
            </form>
          </section>

          {/* ── IN-APP TELEMETRY PREFERENCES ── */}
          <section className={styles.card}>
            <h2 className={styles.cardTitle}>CONSOLE & TELEMETRY PREFERENCES</h2>
            <div className={styles.settingsForm}>
              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={browserNotifications}
                  onChange={(e) => setBrowserNotifications(e.target.checked)}
                />
                <div>
                  <strong>In-App High-Risk Alert Modals</strong>
                  <p>Display emergency popup notifications when a critical phishing or financial scam is flagged.</p>
                </div>
              </label>

              <label className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={highRiskAlertsOnly}
                  onChange={(e) => setHighRiskAlertsOnly(e.target.checked)}
                />
                <div>
                  <strong>High-Risk Threats Only in Feed</strong>
                  <p>Filter out low/medium telemetry and only surface verified critical threats in the security feed.</p>
                </div>
              </label>
            </div>
          </section>

          {/* ── SESSION TERMINATION ── */}
          <section className={styles.dangerCard}>
            <div>
              <h2 className={styles.dangerTitle}>TERMINATE GUARDIAN SESSION</h2>
              <p className={styles.dangerText}>
                Log out of the Guardian console on this device. You will need a new 6-digit access code to log back in.
              </p>
            </div>
            <button className={styles.logoutBtn} onClick={handleLogout}>
              LOGOUT NOW
            </button>
          </section>
        </main>
      </div>
    </GuardianLayout>
  );
}
