// Local accounts and server-side sessions.
//   passwords  scrypt (N=2^15, r=8, p=1), 16-byte salt, constant-time comparison
//   sessions   256-bit random token in an HttpOnly SameSite=Strict cookie; only its SHA-256 is stored
//   CSRF       per-session token that every state-changing request must echo in X-CSRF-Token
//   lockout    8 consecutive failures lock the account for 15 minutes
import { createHash, randomBytes, randomUUID, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import type { Db } from '../db/sqlite';

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, keylen: number, opts: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;

export type Role = 'admin' | 'investigator' | 'viewer';
export type CaseRole = 'lead' | 'investigator' | 'viewer';

export interface User {
  id: string;
  username: string;
  display_name: string;
  role: Role;
  disabled: number;
  created_at: number;
  last_login_at: number | null;
}

export interface Session {
  user: User;
  csrf: string;
  tokenHash: string;
  expiresAt: number;
}

const N = 2 ** 15;
const R = 8;
const P = 1;
const KEYLEN = 64;
export const MIN_PASSWORD = 12;
const LOCK_AFTER = 8;
const LOCK_MS = 15 * 60_000;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, KEYLEN, { N, r: R, p: P, maxmem: 128 * N * R * 2 });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, hash] = parts as [string, string, string, string, string, string];
  const expected = Buffer.from(hash, 'base64');
  const key = await scrypt(password.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: 128 * Number(n) * Number(r) * 2 });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

export function passwordProblem(pw: unknown): string | null {
  if (typeof pw !== 'string') return 'Password is required.';
  if (pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (pw.length > 256) return 'Password is too long.';
  if (/^(.)\1+$/.test(pw)) return 'Password is too repetitive.';
  return null;
}

const tokenHash = (t: string): string => createHash('sha256').update(t).digest('hex');

export class Auth {
  constructor(
    private readonly db: Db,
    private readonly sessionCfg: { idleMinutes: number; maxHours: number },
  ) {}

  userCount(): number {
    return this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM users')?.n ?? 0;
  }

  async createUser(u: { username: string; displayName: string; password: string; role: Role }): Promise<User> {
    if (!/^[a-z0-9._-]{3,40}$/i.test(u.username)) throw new Error('Username: 3–40 letters, digits, dot, dash or underscore.');
    const problem = passwordProblem(u.password);
    if (problem) throw new Error(problem);
    if (this.db.get('SELECT 1 FROM users WHERE username = ?', u.username)) throw new Error('That username is taken.');
    const id = `usr_${randomUUID()}`;
    this.db.run('INSERT INTO users (id, username, display_name, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)', id, u.username, u.displayName.trim().slice(0, 100) || u.username, await hashPassword(u.password), u.role, Date.now());
    return this.user(id) as User;
  }

  user(id: string): User | undefined {
    return this.db.get<User>('SELECT id, username, display_name, role, disabled, created_at, last_login_at FROM users WHERE id = ?', id);
  }

  users(): User[] {
    return this.db.all<User>('SELECT id, username, display_name, role, disabled, created_at, last_login_at FROM users ORDER BY username');
  }

  /** Returns the user on success; a uniform error otherwise (no username enumeration). */
  async login(username: string, password: string): Promise<{ ok: true; user: User } | { ok: false; reason: 'invalid' | 'locked' | 'disabled' }> {
    const row = this.db.get<User & { password_hash: string; failed_logins: number; locked_until: number | null }>('SELECT * FROM users WHERE username = ?', username);
    if (!row) {
      // Spend comparable time so response timing does not reveal whether the user exists.
      await hashPassword(password).catch(() => undefined);
      return { ok: false, reason: 'invalid' };
    }
    if (row.locked_until && row.locked_until > Date.now()) return { ok: false, reason: 'locked' };
    const good = await verifyPassword(password, row.password_hash);
    if (!good) {
      const fails = row.failed_logins + 1;
      this.db.run('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?', fails, fails >= LOCK_AFTER ? Date.now() + LOCK_MS : null, row.id);
      return { ok: false, reason: fails >= LOCK_AFTER ? 'locked' : 'invalid' };
    }
    if (row.disabled) return { ok: false, reason: 'disabled' };
    this.db.run('UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?', Date.now(), row.id);
    return { ok: true, user: this.user(row.id) as User };
  }

  createSession(userId: string, ip: string | null, ua: string | null): { token: string; csrf: string; expiresAt: number } {
    const token = randomBytes(32).toString('base64url');
    const csrf = randomBytes(24).toString('base64url');
    const now = Date.now();
    const expiresAt = now + this.sessionCfg.maxHours * 3600_000;
    this.db.run('INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', tokenHash(token), userId, csrf, now, expiresAt, now, ip, ua?.slice(0, 300) ?? null);
    return { token, csrf, expiresAt };
  }

  session(token: string | undefined): Session | null {
    if (!token || token.length > 200) return null;
    const h = tokenHash(token);
    const s = this.db.get<{ user_id: string; csrf: string; expires_at: number; last_seen_at: number }>('SELECT user_id, csrf, expires_at, last_seen_at FROM sessions WHERE token_hash = ?', h);
    if (!s) return null;
    const now = Date.now();
    if (s.expires_at < now || now - s.last_seen_at > this.sessionCfg.idleMinutes * 60_000) {
      this.db.run('DELETE FROM sessions WHERE token_hash = ?', h);
      return null;
    }
    const user = this.user(s.user_id);
    if (!user || user.disabled) return null;
    if (now - s.last_seen_at > 60_000) this.db.run('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?', now, h);
    return { user, csrf: s.csrf, tokenHash: h, expiresAt: s.expires_at };
  }

  destroySession(tokenHashValue: string): void {
    this.db.run('DELETE FROM sessions WHERE token_hash = ?', tokenHashValue);
  }

  destroyUserSessions(userId: string): void {
    this.db.run('DELETE FROM sessions WHERE user_id = ?', userId);
  }

  async setPassword(userId: string, password: string): Promise<void> {
    const problem = passwordProblem(password);
    if (problem) throw new Error(problem);
    this.db.run('UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = ?', await hashPassword(password), userId);
    this.destroyUserSessions(userId);
  }

  async checkPassword(userId: string, password: string): Promise<boolean> {
    const row = this.db.get<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = ?', userId);
    return !!row && verifyPassword(password, row.password_hash);
  }

  updateUser(id: string, patch: { displayName?: string; role?: Role; disabled?: boolean }): void {
    if (patch.displayName !== undefined) this.db.run('UPDATE users SET display_name = ? WHERE id = ?', patch.displayName.trim().slice(0, 100), id);
    if (patch.role !== undefined) this.db.run('UPDATE users SET role = ? WHERE id = ?', patch.role, id);
    if (patch.disabled !== undefined) {
      this.db.run('UPDATE users SET disabled = ? WHERE id = ?', patch.disabled ? 1 : 0, id);
      if (patch.disabled) this.destroyUserSessions(id);
    }
  }

  purgeExpired(): void {
    this.db.run('DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?', Date.now(), Date.now() - this.sessionCfg.idleMinutes * 60_000);
  }
}

/** The caller's role in a case, or null without access. Administrators can see every case. */
export function caseRole(db: Db, user: User, caseId: string): CaseRole | null {
  const c = db.get<{ created_by: string }>('SELECT created_by FROM cases WHERE id = ?', caseId);
  if (!c) return null;
  if (user.role === 'admin') return 'lead';
  const m = db.get<{ role: CaseRole }>('SELECT role FROM case_members WHERE case_id = ? AND user_id = ?', caseId, user.id);
  if (!m) return null;
  // A global viewer never gets write access, whatever the case membership says.
  return user.role === 'viewer' ? 'viewer' : m.role;
}

export const CASE_RANK: Record<CaseRole, number> = { viewer: 1, investigator: 2, lead: 3 };
