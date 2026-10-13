// Signed-in user, CSRF token and platform limits.
import { api, setCsrf } from './api';
import { createStore } from './store';
import type { PlatformInfo, SessionInfo, User } from './types';

export interface SessionState {
  loaded: boolean;
  user: User | null;
  setupNeeded: boolean;
  platform: PlatformInfo | null;
  expiresAt: number | null;
}

export const session = createStore<SessionState>({ loaded: false, user: null, setupNeeded: false, platform: null, expiresAt: null });

export async function refreshSession(): Promise<SessionState> {
  const s = await api.get<SessionInfo>('/api/auth/session');
  setCsrf(s.csrf);
  session.set({ loaded: true, user: s.user, setupNeeded: s.setupNeeded, platform: s.platform ?? null, expiresAt: s.expiresAt ?? null });
  return session.get();
}

export async function signOut(): Promise<void> {
  try {
    await api.post('/api/auth/logout');
  } finally {
    setCsrf(null);
    session.set({ user: null, platform: null, expiresAt: null });
  }
}

export function canEdit(role: string | undefined): boolean {
  return role === 'lead' || role === 'investigator';
}
