import styles from './Footer.module.css';

export default function Footer() {
  return (
    <footer className={styles.footer}>
      <div className={styles.inner}>
        <div className={styles.left}>
          <div className={styles.logo}>
            <svg viewBox="0 0 32 32" fill="none" width="22" height="22">
              <polygon points="16,3 30,29 2,29" stroke="#00ff9d" strokeWidth="2.5" fill="none"/>
              <line x1="9" y1="21" x2="23" y2="21" stroke="#00ff9d" strokeWidth="2"/>
            </svg>
            <span>AEGIS</span>
          </div>
          <p className={styles.tagline}>Autonomous Vulnerability Neutralization & Intelligence Layer</p>
        </div>


        <div className={styles.right}>
          <span className={styles.badge}>PS3 Autonomy Track</span>
          <span className={styles.copy}>Built for Multi-Agent Hackathon © 2026</span>
        </div>
      </div>
    </footer>
  );
}
