// Content-addressed, write-once blob store.
//   <dataDir>/evidence/ab/cd/<sha256>   uploaded files, byte-for-byte as received
//   <dataDir>/derived/ab/cd/<sha256>    artifacts derived from evidence (mbox members, .msg reconstructions)
//   <dataDir>/reports/ab/cd/<sha256>    generated reports
// Names are hashes, so client file names never reach the file system (no path traversal), the same
// bytes are stored once, and every read can be verified against the name.
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, type ReadStream } from 'node:fs';
import { chmod, mkdir, readFile, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform, type Readable } from 'node:stream';

export type BlobKind = 'evidence' | 'derived' | 'reports';

const SHA256_RE = /^[0-9a-f]{64}$/;

export class IntegrityError extends Error {
  readonly code = 'integrity-error';
  constructor(
    readonly kind: BlobKind,
    readonly expected: string,
    readonly actual: string,
  ) {
    super(`Integrity check failed for ${kind} blob ${expected}: content hashes to ${actual}`);
  }
}

export interface IngestResult {
  sha256: string;
  sha1: string;
  md5: string;
  size: number;
  truncated: boolean;
  /** First bytes, for format detection without re-reading the file. */
  head: Buffer;
  tmpPath: string;
}

export class BlobStore {
  constructor(readonly dataDir: string) {
    for (const d of ['evidence', 'derived', 'reports', 'tmp']) mkdirSync(join(dataDir, d), { recursive: true });
  }

  pathFor(kind: BlobKind, sha256: string): string {
    if (!SHA256_RE.test(sha256)) throw new Error(`invalid blob id ${JSON.stringify(sha256).slice(0, 80)}`);
    return join(this.dataDir, kind, sha256.slice(0, 2), sha256.slice(2, 4), sha256);
  }

  tmpPath(): string {
    return join(this.dataDir, 'tmp', `${Date.now()}-${randomBytes(8).toString('hex')}.part`);
  }

  exists(kind: BlobKind, sha256: string): boolean {
    return existsSync(this.pathFor(kind, sha256));
  }

  /** Streams an upload to a temporary file while hashing it; stops counting at `limit` bytes. */
  async ingestStream(source: Readable, limit: number): Promise<IngestResult> {
    const tmp = this.tmpPath();
    const h256 = createHash('sha256');
    const h1 = createHash('sha1');
    const h5 = createHash('md5');
    let size = 0;
    let truncated = false;
    const headChunks: Buffer[] = [];
    let headLen = 0;
    const meter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        size += chunk.length;
        if (size > limit) {
          truncated = true;
          cb(new Error('file-too-large'));
          return;
        }
        h256.update(chunk);
        h1.update(chunk);
        h5.update(chunk);
        if (headLen < 65536) {
          headChunks.push(chunk.subarray(0, 65536 - headLen));
          headLen += Math.min(chunk.length, 65536 - headLen);
        }
        cb(null, chunk);
      },
    });
    try {
      await pipeline(source, meter, createWriteStream(tmp, { flags: 'wx' }));
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      // Drain whatever is left so the multipart parser can move on to the next file.
      source.resume();
      if (truncated) return { sha256: '', sha1: '', md5: '', size, truncated: true, head: Buffer.alloc(0), tmpPath: '' };
      throw e;
    }
    return { sha256: h256.digest('hex'), sha1: h1.digest('hex'), md5: h5.digest('hex'), size, truncated: false, head: Buffer.concat(headChunks), tmpPath: tmp };
  }

  /** Moves a temp file into the store under its hash. Existing content is never overwritten. */
  async commit(kind: BlobKind, tmpPath: string, sha256: string): Promise<{ existed: boolean }> {
    const dest = this.pathFor(kind, sha256);
    if (existsSync(dest)) {
      await unlink(tmpPath).catch(() => undefined);
      return { existed: true };
    }
    await mkdir(dirname(dest), { recursive: true });
    try {
      await rename(tmpPath, dest);
    } catch (e) {
      // Lost a race with an identical upload: the stored copy wins.
      if (existsSync(dest)) {
        await unlink(tmpPath).catch(() => undefined);
        return { existed: true };
      }
      throw e;
    }
    await chmod(dest, 0o444).catch(() => undefined);
    return { existed: false };
  }

  async putBytes(kind: BlobKind, bytes: Uint8Array): Promise<{ sha256: string; existed: boolean }> {
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (this.exists(kind, sha256)) return { sha256, existed: true };
    const tmp = this.tmpPath();
    await writeFile(tmp, bytes, { flag: 'wx' });
    const r = await this.commit(kind, tmp, sha256);
    return { sha256, existed: r.existed };
  }

  /** Reads a blob; by default verifies that its content still hashes to its name. */
  async read(kind: BlobKind, sha256: string, verify = true): Promise<Buffer> {
    const buf = await readFile(this.pathFor(kind, sha256));
    if (verify) {
      const actual = createHash('sha256').update(buf).digest('hex');
      if (actual !== sha256) throw new IntegrityError(kind, sha256, actual);
    }
    return buf;
  }

  async verify(kind: BlobKind, sha256: string): Promise<{ ok: boolean; actual: string | null; size: number | null }> {
    const path = this.pathFor(kind, sha256);
    if (!existsSync(path)) return { ok: false, actual: null, size: null };
    const h = createHash('sha256');
    let size = 0;
    for await (const chunk of createReadStream(path)) {
      h.update(chunk as Buffer);
      size += (chunk as Buffer).length;
    }
    const actual = h.digest('hex');
    return { ok: actual === sha256, actual, size };
  }

  stream(kind: BlobKind, sha256: string): ReadStream {
    return createReadStream(this.pathFor(kind, sha256));
  }

  async size(kind: BlobKind, sha256: string): Promise<number> {
    return (await stat(this.pathFor(kind, sha256))).size;
  }

  /** Deletes a blob (case deletion). Callers must check that no other record references it. */
  async remove(kind: BlobKind, sha256: string): Promise<void> {
    const path = this.pathFor(kind, sha256);
    await chmod(path, 0o644).catch(() => undefined);
    await rm(path, { force: true });
  }
}
