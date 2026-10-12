// Thin wrapper over node:sqlite: WAL mode, foreign keys, statement cache, nested transactions,
// and versioned migrations. One process writes each database; worker threads open read-only views.
import { DatabaseSync, type StatementSync, type SQLInputValue } from 'node:sqlite';

export type Param = SQLInputValue;

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export class Db {
  readonly raw: DatabaseSync;
  readonly path: string;
  private stmts = new Map<string, StatementSync>();
  private depth = 0;

  constructor(path: string, opts: { readOnly?: boolean } = {}) {
    this.path = path;
    this.raw = new DatabaseSync(path, opts.readOnly ? { readOnly: true } : {});
    this.raw.exec('PRAGMA busy_timeout = 10000');
    if (!opts.readOnly) {
      this.raw.exec('PRAGMA journal_mode = WAL');
      this.raw.exec('PRAGMA synchronous = NORMAL');
    }
    this.raw.exec('PRAGMA foreign_keys = ON');
  }

  private stmt(sql: string): StatementSync {
    let s = this.stmts.get(sql);
    if (!s) {
      s = this.raw.prepare(sql);
      if (this.stmts.size > 500) this.stmts.clear();
      this.stmts.set(sql, s);
    }
    return s;
  }

  run(sql: string, ...params: Param[]): { changes: number; lastInsertRowid: number } {
    const r = this.stmt(sql).run(...params);
    return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
  }

  get<T>(sql: string, ...params: Param[]): T | undefined {
    return this.stmt(sql).get(...params) as T | undefined;
  }

  all<T>(sql: string, ...params: Param[]): T[] {
    return this.stmt(sql).all(...params) as T[];
  }

  exec(sql: string): void {
    this.raw.exec(sql);
  }

  /** Runs fn in a transaction (a savepoint when nested). Rolls back on any exception. */
  tx<T>(fn: () => T): T {
    const name = `sp${this.depth}`;
    this.raw.exec(this.depth === 0 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${name}`);
    this.depth++;
    try {
      const out = fn();
      this.depth--;
      this.raw.exec(this.depth === 0 ? 'COMMIT' : `RELEASE ${name}`);
      return out;
    } catch (e) {
      this.depth--;
      this.raw.exec(this.depth === 0 ? 'ROLLBACK' : `ROLLBACK TO ${name}; RELEASE ${name}`);
      throw e;
    }
  }

  migrate(migrations: Migration[]): number {
    this.raw.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)');
    const applied = new Set(this.all<{ version: number }>('SELECT version FROM schema_migrations').map((r) => r.version));
    let n = 0;
    for (const m of [...migrations].sort((a, b) => a.version - b.version)) {
      if (applied.has(m.version)) continue;
      this.tx(() => {
        this.raw.exec(m.sql);
        this.run('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)', m.version, m.name, Date.now());
      });
      n++;
    }
    return n;
  }

  close(): void {
    this.stmts.clear();
    this.raw.close();
  }
}
