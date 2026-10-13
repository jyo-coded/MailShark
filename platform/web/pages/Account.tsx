// Own account: profile, password change, display preferences.
import { useState } from 'preact/hooks';
import { api } from '../lib/api';
import { navigate } from '../lib/router';
import { session } from '../lib/session';
import { toast, toastError, usePref, useStore } from '../lib/store';
import { applyTheme, type ThemePref } from '../components/Shell';
import { Field, KV, Panel, Time } from '../components/ui';

export function Account() {
  const s = useStore(session);
  const [f, setF] = useState({ current: '', password: '', confirm: '' });
  const [theme, setTheme] = usePref<ThemePref>('theme', 'system');
  const u = s.user;
  if (!u) return null;
  const change = async (): Promise<void> => {
    try {
      await api.post('/api/auth/password', { current: f.current, password: f.password });
      toast('Password changed. Sign in again with the new password.', 'success');
      session.set({ user: null });
      navigate('/login');
    } catch (e) {
      toastError(e);
    }
  };
  return (
    <div class="page" style={{ maxWidth: '900px' }}>
      <div class="page-head">
        <div>
          <div class="eyebrow">You</div>
          <h1>Account</h1>
        </div>
      </div>
      <div class="grid grid-2">
        <Panel title="Profile">
          <KV
            rows={[
              ['Name', u.displayName],
              ['Username', <span class="mono">{u.username}</span>],
              ['Platform role', u.role],
              ['Last sign-in', <Time ms={u.lastLoginAt} />],
              ['Session expires', <Time ms={s.expiresAt} />],
            ]}
          />
          <div style={{ marginTop: '16px' }}>
            <Field label="Theme" id="th">
              <select
                id="th"
                class="select"
                value={theme}
                onChange={(e) => {
                  const v = (e.target as HTMLSelectElement).value as ThemePref;
                  setTheme(v);
                  applyTheme(v);
                }}
              >
                <option value="system">Follow the system</option>
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            </Field>
          </div>
        </Panel>
        <Panel title="Change password">
          <div class="col" style={{ gap: 'var(--sp-3)' }}>
            <Field label="Current password" id="cp">
              <input id="cp" type="password" class="input" autocomplete="current-password" value={f.current} onInput={(e) => setF({ ...f, current: (e.target as HTMLInputElement).value })} />
            </Field>
            <Field label="New password" id="np" hint="At least 12 characters. All your sessions are signed out.">
              <input id="np" type="password" class="input" autocomplete="new-password" value={f.password} onInput={(e) => setF({ ...f, password: (e.target as HTMLInputElement).value })} />
            </Field>
            <Field label="Confirm" id="cf" hint={f.confirm && f.confirm !== f.password ? 'Does not match.' : undefined}>
              <input id="cf" type="password" class="input" autocomplete="new-password" value={f.confirm} onInput={(e) => setF({ ...f, confirm: (e.target as HTMLInputElement).value })} />
            </Field>
            <div>
              <button class="btn btn-primary" disabled={!f.current || f.password.length < 12 || f.password !== f.confirm} onClick={() => void change().catch(toastError)}>
                Change password
              </button>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
