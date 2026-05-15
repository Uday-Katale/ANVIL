import { useEffect, useRef } from 'react';
import styles from './HeroSection.module.css';

function MatrixRain() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const chars = '0123456789ABCDEF<>{}[]|/\\RECON EXPLOIT PATCH VERIFY';
    const fontSize = 13;
    const cols = Math.floor(canvas.width / fontSize);
    const drops = Array(cols).fill(0).map(() => Math.random() * -100);

    const draw = () => {
      ctx.fillStyle = 'rgba(6, 6, 11, 0.055)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px 'Share Tech Mono', monospace`;

      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const progress = drops[i] / (canvas.height / fontSize);
        const alpha = Math.max(0.05, 0.6 - progress * 0.5);
        const isGreen = Math.random() > 0.9;
        ctx.fillStyle = isGreen
          ? `rgba(0, 255, 157, ${alpha})`
          : `rgba(0, 180, 255, ${alpha * 0.4})`;
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 0.5;
      }
    };

    const interval = setInterval(draw, 40);
    return () => {
      clearInterval(interval);
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return <canvas ref={canvasRef} className={styles.matrix} />;
}

export default function HeroSection({ onScrollToDashboard }) {
  return (
    <section className={styles.hero}>
      <MatrixRain />

      <div className={styles.grid}></div>

      <div className={styles.content}>
        <div className={styles.tag}>
          <span className={styles.tagDot}></span>
          PS3 AUTONOMY TRACK — MULTI-AGENT SECURITY
        </div>

        <h1 className={styles.title}>
          <span className={styles.titleLine1} data-text="AUTONOMOUS">AUTONOMOUS</span>
          <span className={styles.titleLine2} data-text="SECURITY">SECURITY</span>
          <span className={styles.titleAccent} data-text="ENGINE">ENGINE</span>
        </h1>

        <p className={styles.subtitle}>
          A self-directed AI system that finds vulnerabilities, proves they're real,
          <br />and generates the patch — without a human writing a single line of security code.
        </p>

        <div className={styles.stats}>
          <div className={styles.stat}>
            <span className={styles.statValue}>4</span>
            <span className={styles.statLabel}>Autonomous Agents</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>0</span>
            <span className={styles.statLabel}>Human Interventions</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>∞</span>
            <span className={styles.statLabel}>Petri Net States</span>
          </div>
          <div className={styles.statDivider}></div>
          <div className={styles.stat}>
            <span className={styles.statValue}>24s</span>
            <span className={styles.statLabel}>Avg Detection Time</span>
          </div>
        </div>

        <div className={styles.ctas}>
          <button className={styles.ctaPrimary} onClick={onScrollToDashboard}>
            <span>Launch Mission Control</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="18" height="18">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7l5 5-5 5M6 12h12"/>
            </svg>
          </button>
          <a
            href="https://github.com/DevOpsDreamer/ANVIL"
            target="_blank"
            rel="noopener noreferrer"
            className={styles.ctaSecondary}
          >
            <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
              <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
            </svg>
            View Source
          </a>
        </div>

        <div className={styles.techStack}>
          {['FastAPI', 'Redis Streams', 'SQLite WAL', 'Celery', 'LangGraph', 'Omium SDK', 'Pydantic v2', 'Docker'].map(t => (
            <span key={t} className={styles.tech}>{t}</span>
          ))}
        </div>
      </div>

      <div className={styles.scrollIndicator}>
        <span>SCROLL TO DASHBOARD</span>
        <div className={styles.scrollArrow}></div>
      </div>
    </section>
  );
}
