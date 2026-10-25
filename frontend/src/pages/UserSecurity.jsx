import { Link } from 'react-router-dom';
import UserLayout from '../components/UserLayout';

export default function UserSecurity() {
  const securityModules = [
    {
      icon: '💬',
      title: 'Scam Message & SMS Filter',
      desc: 'Real-time NLP and heuristic classifier inspecting SMS, WhatsApp, and email communications for social engineering, urgency triggers, and payment coercion.',
      status: 'ACTIVE',
      link: '/user/messages',
      linkText: 'Open Message Scanner →',
    },
    {
      icon: '🌐',
      title: 'Malicious URL & Zero-Day Sentry',
      desc: 'Layered hybrid detection engine evaluating 20+ static URL structural indicators and trained Random Forest model against zero-day phishing campaigns.',
      status: 'ACTIVE',
      link: '/user/link-checker',
      linkText: 'Open Link Checker →',
    },
    {
      icon: '📑',
      title: 'Document & QR Threat Sentinel',
      desc: 'Multi-engine scanner executing OCR text extraction, embedded QR code payload decoding, and link correlation across PDFs, DOCXs, and images.',
      status: 'ACTIVE',
      link: '/user/document-checker',
      linkText: 'Open Document Scanner →',
    },
    {
      icon: '🎙️',
      title: 'Live Voice Scam & Vishing Guardian',
      desc: 'Real-time Malayalam + English two-person voice call monitoring with semantic vishing risk analysis, credential theft detection, and advisory warnings.',
      status: 'ACTIVE',
      link: '/user/live-voice',
      linkText: 'Launch Live Voice Guardian →',
    },
    {
      icon: '🛡️',
      title: 'Deepfake & Payment Fraud Firewall',
      desc: 'Continuous threat heuristics detecting synthetic voice impersonation, deceptive UPI payment handles, and urgent unauthorized fund requests.',
      status: 'ACTIVE',
      link: '/user/assistant',
      linkText: 'Consult AI Assistant →',
    },
  ];

  return (
    <UserLayout
      eyebrow="DEFENSE ARCHITECTURE"
      title="ACTIVE SECURITY SENTINELS"
      subtitle="KAVACH security engine operates four synchronized protection sentinels to ensure comprehensive personal and family safety."
    >
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '24px',
          width: '100%',
        }}
      >
        {securityModules.map((mod) => (
          <div
            key={mod.title}
            style={{
              background: 'rgba(26, 46, 94, 0.45)',
              border: '1px solid rgba(217, 203, 194, 0.15)',
              borderRadius: '6px',
              padding: '28px 30px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '20px',
              backdropFilter: 'blur(8px)',
              boxShadow: '0 10px 30px rgba(10, 20, 50, 0.3)',
            }}
          >
            <div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '14px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontSize: '24px' }}>{mod.icon}</span>
                  <h3
                    style={{
                      fontFamily: 'Space Grotesk, sans-serif',
                      fontSize: '17px',
                      fontWeight: 800,
                      color: 'var(--kavach-swan-wing)',
                      margin: 0,
                    }}
                  >
                    {mod.title}
                  </h3>
                </div>
                <span
                  style={{
                    background: 'rgba(34, 197, 94, 0.18)',
                    color: '#86efac',
                    border: '1px solid #22c55e',
                    fontSize: '10px',
                    fontWeight: 800,
                    letterSpacing: '1px',
                    padding: '3px 8px',
                    borderRadius: '3px',
                    textTransform: 'uppercase',
                  }}
                >
                  {mod.status}
                </span>
              </div>
              <p
                style={{
                  fontSize: '13.5px',
                  color: 'var(--kavach-shellstone)',
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                {mod.desc}
              </p>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderTop: '1px solid rgba(217, 203, 194, 0.1)',
                paddingTop: '16px',
              }}
            >
              <span
                style={{
                  fontSize: '10.5px',
                  color: 'var(--kavach-quicksand)',
                  textTransform: 'uppercase',
                  letterSpacing: '1px',
                  fontWeight: 700,
                }}
              >
                Telemetry: Continuous 24/7
              </span>
              <Link
                to={mod.link}
                style={{
                  fontSize: '12px',
                  color: 'var(--kavach-quicksand)',
                  fontWeight: 700,
                  textDecoration: 'none',
                  transition: 'opacity 0.2s ease',
                }}
              >
                {mod.linkText}
              </Link>
            </div>
          </div>
        ))}
      </div>
    </UserLayout>
  );
}
