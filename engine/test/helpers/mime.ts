// Test helper: builds RFC 5322 / MIME messages so fixtures are explicit and reproducible.

export interface FixtureAttachment {
  filename: string;
  contentType: string;
  content: Uint8Array | string;
  inline?: boolean;
  cid?: string;
}

export interface FixtureSpec {
  headers: [string, string][];
  text?: string;
  html?: string;
  attachments?: FixtureAttachment[];
}

function b64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  const s = Buffer.from(bin, 'latin1').toString('base64');
  return s.replace(/.{1,76}/g, (m) => m + '\r\n').trimEnd();
}

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

let counter = 0;
function boundary(tag: string): string {
  counter++;
  return `----=_MS_${tag}_${counter.toString(16).padStart(6, '0')}`;
}

export function buildEml(spec: FixtureSpec): string {
  const lines: string[] = spec.headers.map(([k, v]) => `${k}: ${v}`);
  lines.push('MIME-Version: 1.0');

  const bodyParts: string[] = [];
  const alt: string[] = [];
  if (spec.text !== undefined) alt.push(`Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(enc(spec.text))}`);
  if (spec.html !== undefined) alt.push(`Content-Type: text/html; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(enc(spec.html))}`);

  const atts = spec.attachments ?? [];
  if (!atts.length && alt.length === 1) {
    lines.push(alt[0] as string);
    return lines.join('\r\n') + '\r\n';
  }

  let content: string;
  if (alt.length > 1) {
    const bAlt = boundary('alt');
    content = `Content-Type: multipart/alternative; boundary="${bAlt}"\r\n\r\n` + alt.map((p) => `--${bAlt}\r\n${p}\r\n`).join('') + `--${bAlt}--`;
  } else content = alt[0] ?? `Content-Type: text/plain; charset="utf-8"\r\n\r\n`;

  if (!atts.length) {
    lines.push(content);
    return lines.join('\r\n') + '\r\n';
  }
  const bMix = boundary('mix');
  bodyParts.push(content);
  for (const a of atts) {
    const bytes = typeof a.content === 'string' ? enc(a.content) : a.content;
    const disp = a.inline ? 'inline' : 'attachment';
    bodyParts.push(
      `Content-Type: ${a.contentType}; name="${a.filename}"\r\nContent-Disposition: ${disp}; filename="${a.filename}"\r\n` +
        (a.cid ? `Content-ID: <${a.cid}>\r\n` : '') +
        `Content-Transfer-Encoding: base64\r\n\r\n${b64(bytes)}`,
    );
  }
  lines.push(`Content-Type: multipart/mixed; boundary="${bMix}"`);
  lines.push('');
  lines.push(bodyParts.map((p) => `--${bMix}\r\n${p}\r\n`).join('') + `--${bMix}--`);
  return lines.join('\r\n') + '\r\n';
}

/** Headers a Gmail mailbox adds on delivery. */
export function gmailReceived(opts: { ip: string; host: string; auth: string; date?: string; spfLine?: string; returnPath?: string }): [string, string][] {
  const date = opts.date ?? 'Mon, 21 Sep 2026 08:49:05 -0700 (PDT)';
  return [
    ['Delivered-To', 'victim@gmail.com'],
    ['Received', `by 2002:a05:612c:2c92:b0:605:d55e:8f60 with SMTP id iu18csp12415996vqb; ${date}`],
    ['X-Received', `by 2002:a05:6214:1c8e:b0:6a1:8f44 with SMTP id xyz; ${date}`],
    ['ARC-Seal', 'i=1; a=rsa-sha256; t=1790005745; cv=none; d=google.com; s=arc-20240605; b=abc'],
    ['ARC-Authentication-Results', `i=1; mx.google.com; ${opts.auth}`],
    ['Return-Path', `<${opts.returnPath ?? 'bounce@' + opts.host.split('.').slice(-2).join('.')}>`],
    ['Received', `from ${opts.host} (${opts.host}. [${opts.ip}]) by mx.google.com with ESMTPS id 6a1803df08f44-91260be7b36si82348806d6.70.2026.09.21.08.49.05 for <victim@gmail.com> (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256); ${date}`],
    ['Received-SPF', opts.spfLine ?? `pass (google.com: domain designates ${opts.ip} as permitted sender) client-ip=${opts.ip};`],
    ['Authentication-Results', `mx.google.com; ${opts.auth}`],
  ];
}
