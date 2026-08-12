import { useState, useEffect } from 'react';
import { api } from '../services/api';
import UserNav from '../components/UserNav';
import styles from './UserDashboard.module.css';

export default function UserSecurity() {
  const [userName, setUserName] = useState('');

  useEffect(() => {
    api.getMe().then((d) => setUserName(d.full_name)).catch(() => null);
  }, []);

  const securityModules = [
    { title: 'Scam Message & SMS Filter', desc: 'Analyzes incoming messages and SMS for fraudulent patterns, deceptive links, and social engineering attempts.', status: 'ACTIVE' },
    { title: 'Deepfake Voice Firewall', desc: 'Real-time frequency and biometric analysis detecting synthetic audio impersonation in live voice calls.', status: 'ACTIVE' },
    { title: 'Malicious URL & Domain Scanner', desc: 'Validates URLs against zero-day phishing databases and cryptographic certificate spoofing.', status: 'ACTIVE' },
    { title: 'Payment & UPI Transaction Sentry', desc: 'Monitors fraudulent QR codes, unverified payment gateway prompts, and deceptive bank requests.', status: 'ACTIVE' },
  ];

  return (
    <div className={styles.page}>
      <UserNav userName={userName} />

      <main className={styles.main}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <h1 className={styles.heroHeading} style={{ fontSize: '38px' }}>
            ACTIVE SECURITY SHIELDS
          </h1>
          <p className={styles.heroSub}>
            KAVACH security engine operates across four dedicated protection layers to ensure total digital safety.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '24px' }}>
          {securityModules.map((mod) => (
            <div key={mod.title} style={{ background: '#ffffff', border: '1px solid #ebe7df', padding: '32px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <h3 style={{ fontFamily: 'Space Grotesk, sans-serif', fontSize: '18px', fontWeight: 800, color: '#1a3325' }}>{mod.title}</h3>
                  <span className={styles.statusPill}>{mod.status}</span>
                </div>
                <p style={{ fontSize: '14px', color: '#4a5d4e', lineHeight: 1.6 }}>{mod.desc}</p>
              </div>
              <div style={{ fontSize: '11px', color: '#737373', textTransform: 'uppercase', letterSpacing: '1px', borderTop: '1px solid #f5f2eb', paddingTop: '14px' }}>
                Protection Engine: Active 24/7
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
