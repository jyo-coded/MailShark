// First-run setup (creates the administrator with the console setup token) and sign-in.
import { useState } from 'preact/hooks';
import { LogIn, ShieldCheck } from 'lucide-preact';
import { api, ApiError } from '../lib/api';
import { navigate, useRoute } from '../lib/router';
import { refreshSession } from '../lib/session';
import { Field, Notice } from '../components/ui';
import { SharkMark } from '../components/Shell';

function Brand({ sub }: { sub: string }) {
  return (
    <div class="auth-brand">
      <SharkMark size={40} />
      <div>
        <h1>MailShark Forensics</h1>
        <p>{sub}</p>
      </div>
    </div>
  );
}

export function Login() {
  const { query } = useRoute();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: Event): Promise<void> => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/auth/login', { username, password });
      await refreshSession();
      const next = query.get('next');
      navigate(next && next.startsWith('/') && !next.startsWith('//') ? next : '/', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div class="auth">
      <div class="auth-card">
        <Brand sub="Email evidence analysis and campaign intelligence" />
        <form class="panel" onSubmit={submit}>
          <div class="panel-body">
            {error && <Notice c="danger">{error}</Notice>}
            <Field label="Username" id="u">
              <input id="u" class="input" autocomplete="username" value={username} onInput={(e) => setUsername((e.target as HTMLInputElement).value)} required />
            </Field>
            <Field label="Password" id="p">
              <input id="p" class="input" type="password" autocomplete="current-password" value={password} onInput={(e) => setPassword((e.target as HTMLInputElement).value)} required />
            </Field>
            <button class="btn btn-primary" type="submit" disabled={busy || !username || !password}>
              <LogIn /> {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
        <div class="auth-foot">Self-hosted instance · every sign-in and case action is recorded in a tamper-evident audit log.</div>
      </div>
    </div>
  );
}

export function Setup() {
  const [f, setF] = useState({ token: '', username: '', displayName: '', password: '', confirm: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: Event) => setF({ ...f, [k]: (e.target as HTMLInputElement).value });
  const mismatch = f.confirm.length > 0 && f.confirm !== f.password;
  const submit = async (e: Event): Promise<void> => {
    e.preventDefault();
    if (mismatch) return;
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/setup', { token: f.token.trim(), username: f.username, displayName: f.displayName, password: f.password });
      await api.post('/api/auth/login', { username: f.username, password: f.password });
      await refreshSession();
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Setup failed.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div class="auth">
      <div class="auth-card">
        <Brand sub="First-run setup: create the administrator account" />
        <form class="panel" onSubmit={submit}>
          <div class="panel-body">
            <Notice>
              The one-time <b>setup token</b> is printed in the server console when the platform starts without any users. It proves you have access to the server.
            </Notice>
            {error && <Notice c="danger">{error}</Notice>}
            <Field label="Setup token" id="t">
              <input id="t" class="input mono" autocomplete="off" value={f.token} onInput={set('token')} required />
            </Field>
            <Field label="Username" id="u" hint="3–40 characters: letters, digits, dot, dash, underscore.">
              <input id="u" class="input" autocomplete="username" value={f.username} onInput={set('username')} required />
            </Field>
            <Field label="Display name" id="d">
              <input id="d" class="input" value={f.displayName} onInput={set('displayName')} />
            </Field>
            <Field label="Password" id="p" hint="At least 12 characters. Use a passphrase.">
              <input id="p" class="input" type="password" autocomplete="new-password" value={f.password} onInput={set('password')} required />
            </Field>
            <Field label="Confirm password" id="c" hint={mismatch ? 'The passwords do not match.' : undefined}>
              <input id="c" class="input" type="password" autocomplete="new-password" value={f.confirm} onInput={set('confirm')} required />
            </Field>
            <button class="btn btn-primary" type="submit" disabled={busy || mismatch || !f.token || !f.username || !f.password}>
              <ShieldCheck /> {busy ? 'Creating…' : 'Create administrator'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
