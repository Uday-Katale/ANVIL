import { useState, useEffect } from 'react';
import styles from './NavBar.module.css';

export default function NavBar({ user, onLogout }) {
  const [time, setTime] = useState(new Date());
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    const s = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', s);
    return () => { clearInterval(t); window.removeEventListener('scroll', s); };
  }, []);

  const fmt = (n) => String(n).padStart(2, '0');
  const timeStr = `${fmt(time.getHours())}:${fmt(time.getMinutes())}:${fmt(time.getSeconds())}`;

  return (
    <nav className={`${styles.nav} ${scrolled ? styles.scrolled : ''}`}>
      <div className={styles.inner}>
        <div className={styles.logo}>
          <svg className={styles.logoIcon} viewBox="0 0 32 32" fill="none">
            <polygon points="16,3 30,29 2,29" stroke="#00ff9d" strokeWidth="2.5" fill="none"/>
            <line x1="9" y1="21" x2="23" y2="21" stroke="#00ff9d" strokeWidth="2"/>
          </svg>
          <span className={styles.logoText}>A.E.G.I.S.</span>
          <span className={styles.logoBadge}>v1.0.0</span>
        </div>

        <div className={styles.links}>
          <a href="#dashboard" className={styles.link}>Dashboard</a>
          <a href="#architecture" className={styles.link}>Architecture</a>
          <a href="#how-it-works" className={styles.link}>How It Works</a>
          
        </div>

        
        {user && (
          <div className={styles.navUser}>
            <img src={user.avatar_url} alt={user.login} className={styles.navAvatar} />
            <span className={styles.navLogin}>@{user.login}</span>
          </div>
        )}
        <div className={styles.status}>
          <span className={styles.statusDot}></span>
          <span className={styles.statusText}>SYSTEM ONLINE</span>
          <span className={styles.clock}>{timeStr}</span>
        </div>
      </div>
    </nav>
  );
}
