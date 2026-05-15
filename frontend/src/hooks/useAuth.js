import { useState, useEffect, useCallback } from 'react';
import { getMe, loginWithGitHub, logout as apiLogout } from '../api/client.js';

/**
 * Manages GitHub OAuth state.
 * Returns { user, loading, login, logout }
 */
export function useAuth() {
  const [user, setUser] = useState(null);       // null = unauthenticated
  const [loading, setLoading] = useState(true);  // checking auth on mount

  useEffect(() => {
    getMe().then(u => {
      setUser(u);
      setLoading(false);
    });
  }, []);

  const login = useCallback(() => loginWithGitHub(), []);

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
  }, []);

  return { user, loading, login, logout };
}
