import { useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import FeatureCard from '../components/FeatureCard';
import styles from './Landing.module.css';

/* ──────────────────────────────────────────────
   CSS-only shield / radar hero illustration
   ────────────────────────────────────────────── */
function ShieldIllustration() {
  return (
    <div className={styles.shieldWrap} aria-hidden="true">
      {/* Orbit rings */}
      <div className={`${styles.ring} ${styles.ring1}`} />
      <div className={`${styles.ring} ${styles.ring2}`} />
      <div className={`${styles.ring} ${styles.ring3}`} />

      {/* Shield body */}
      <div className={styles.shield}>
        <div className={styles.shieldInner}>
          <span className={styles.shieldIcon}>⚡</span>
          <div className={styles.scanLine} />
        </div>
      </div>

      {/* Floating threat nodes */}
      <div className={`${styles.node} ${styles.nodeBlue}`}  />
      <div className={`${styles.node} ${styles.nodePurple}`}/>
      <div className={`${styles.node} ${styles.nodeGreen}`} />
      <div className={`${styles.node} ${styles.nodeRed}`}   />

      {/* Scan indicators */}
      <div className={styles.radarSweep} />
    </div>
  );
}

/* ──────────────────────────────────────────────
   Features data
   ────────────────────────────────────────────── */
const features = [
  {
    icon: '🚨',
    title: 'Scam Detection',
    desc: 'Real-time detection of suspicious messages, interactions, and fraudulent content using AI pattern recognition.',
    color: 'blue',
  },
  {
    icon: '🎙️',
    title: 'Voice Scam Protection',
    desc: 'Analyze suspicious voice calls and detect possible deepfake voice attacks and impersonation attempts.',
    color: 'purple',
  },
  {
    icon: '🔗',
    title: 'Phishing Protection',
    desc: 'Identify malicious links, suspicious messages, and fraudulent websites before you fall victim.',
    color: 'green',
  },
  {
    icon: '💳',
    title: 'Payment Protection',
    desc: 'Warn users about suspicious payment requests, fake UPI IDs, and financial fraud attempts in real time.',
    color: 'orange',
  },
  {
    icon: '🤖',
    title: 'AI Risk Analysis',
    desc: 'AI-based evaluation provides a comprehensive risk score and detailed explanation of detected threats.',
    color: 'pink',
  },
  {
    icon: '📄',
    title: 'Document Protection',
    desc: 'Analyze suspicious documents, attachments, and digital content for hidden malware or misleading data.',
    color: 'teal',
  },
];

/* ──────────────────────────────────────────────
   How It Works steps
   ────────────────────────────────────────────── */
const steps = [
  {
    step: '01',
    title: 'Encounter',
    desc: 'User encounters a suspicious message, link, call, or document in their digital environment.',
  },
  {
    step: '02',
    title: 'Submit',
    desc: 'Kavach analyzes the suspicious content using multi-modal AI analysis pipelines.',
  },
  {
    step: '03',
    title: 'Evaluate',
    desc: 'AI engine evaluates threat signals and generates a comprehensive risk assessment.',
  },
  {
    step: '04',
    title: 'Protect',
    desc: 'Kavach delivers an instant warning with explanation and recommended protective actions.',
  },
];

/* ──────────────────────────────────────────────
   Landing Page
   ────────────────────────────────────────────── */
export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className={styles.page}>
      <Navbar />

      {/* ── HERO ── */}
      <section id="hero" className={styles.hero}>
        {/* Background glow orbs */}
        <div className={styles.orb1} aria-hidden="true" />
        <div className={styles.orb2} aria-hidden="true" />

        <div className={styles.heroContent}>
          <div className={styles.heroBadge}>
            <span className={styles.heroBadgeDot} />
            AI-Powered Security Platform
          </div>

          <h1 className={styles.heroTitle}>
            Your AI Guardian<br />
            <span className={styles.heroTitleAccent}>Against Digital Scams</span>
          </h1>

          <p className={styles.heroDesc}>
            KAVACH uses advanced artificial intelligence to detect phishing attacks,
            voice scams, deepfakes, and fraudulent digital interactions — keeping you
            safe before harm is done.
          </p>

          <div className={styles.heroButtons}>
            <button
              id="hero-get-started"
              className={styles.btnPrimary}
              onClick={() => navigate('/register')}
              aria-label="Create your KAVACH account"
            >
              Get Started Free
              <span aria-hidden="true">→</span>
            </button>
            <button
              id="hero-login"
              className={styles.btnOutline}
              onClick={() => navigate('/login')}
              aria-label="Log in to KAVACH"
            >
              Login
            </button>
          </div>

          <div className={styles.heroStats}>
            <div className={styles.stat}>
              <span className={styles.statValue}>6+</span>
              <span className={styles.statLabel}>Protection Modules</span>
            </div>
            <div className={styles.statDivider} />
            <div className={styles.stat}>
              <span className={styles.statValue}>AI</span>
              <span className={styles.statLabel}>Powered Analysis</span>
            </div>
            <div className={styles.statDivider} />
            <div className={styles.stat}>
              <span className={styles.statValue}>24/7</span>
              <span className={styles.statLabel}>Always Active</span>
            </div>
          </div>
        </div>

        {/* Visual illustration */}
        <div className={styles.heroVisual}>
          <ShieldIllustration />
        </div>
      </section>

      {/* ── FEATURES ── */}
      <section id="features" className={styles.section}>
        <div className={styles.sectionContainer}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionEyebrow}>Protection Modules</span>
            <h2 className={styles.sectionTitle}>Everything You Need to Stay Safe</h2>
            <p className={styles.sectionDesc}>
              KAVACH provides comprehensive AI-powered protection across all vectors of digital threats.
            </p>
          </div>

          <div className={styles.featuresGrid}>
            {features.map((f) => (
              <FeatureCard key={f.title} {...f} />
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how-it-works" className={styles.howSection}>
        <div className={styles.sectionContainer}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionEyebrow}>The Process</span>
            <h2 className={styles.sectionTitle}>How KAVACH Works</h2>
            <p className={styles.sectionDesc}>
              From suspicious content to protection in four seamless AI-powered steps.
            </p>
          </div>

          <div className={styles.stepsGrid}>
            {steps.map((s, i) => (
              <div key={s.step} className={styles.stepCard}>
                <div className={styles.stepNum}>{s.step}</div>
                {i < steps.length - 1 && <div className={styles.stepConnector} aria-hidden="true" />}
                <h3 className={styles.stepTitle}>{s.title}</h3>
                <p className={styles.stepDesc}>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className={styles.ctaSection}>
        <div className={styles.ctaOrb1} aria-hidden="true" />
        <div className={styles.ctaOrb2} aria-hidden="true" />
        <div className={styles.ctaContent}>
          <h2 className={styles.ctaTitle}>
            Protect Yourself Before the Scam Happens
          </h2>
          <p className={styles.ctaDesc}>
            Join KAVACH and let AI be your digital guardian. Stay safe. Stay alert. Stay protected.
          </p>
          <button
            id="cta-get-started"
            className={styles.btnPrimary}
            onClick={() => navigate('/register')}
            aria-label="Create your KAVACH account for free"
          >
            Get Started Free
            <span aria-hidden="true">→</span>
          </button>
        </div>
      </section>

      <Footer />
    </div>
  );
}
