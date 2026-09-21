// MailShark feasibility probe: Gmail raw MIME, fetched in memory (nothing written to disk).
// Usage: open any email in Gmail → DevTools (F12) → Console → paste → Enter.
// Chrome may ask you to type "allow pasting" first.
(async () => {
  const nodes = document.querySelectorAll('div[data-legacy-message-id]');
  if (!nodes.length) return console.warn('MailShark: open an email first.');
  const id = nodes[nodes.length - 1].getAttribute('data-legacy-message-id');

  // Same endpoint Gmail's own "Download message" uses; the session cookie authenticates it.
  const url = `${location.origin}${location.pathname}?view=att&th=${id}&attid=0&disp=comp&safe=1&zw`;
  const t0 = performance.now();
  const buf = await (await fetch(url, { credentials: 'include' })).arrayBuffer();
  const ms = Math.round(performance.now() - t0);
  const raw = new TextDecoder('latin1').decode(buf);

  const sha256 = [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))]
    .map(b => b.toString(16).padStart(2, '0')).join('');

  const head = raw.split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' ');
  const headers = head.split(/\r?\n/).map(l => {
    const i = l.indexOf(':');
    return [l.slice(0, i).toLowerCase(), l.slice(i + 1).trim()];
  });
  const get = n => headers.filter(([k]) => k === n).map(([, v]) => v);

  console.log(`%cMailShark probe: ${buf.byteLength} bytes of raw MIME in ${ms} ms, never touched disk`,
    'font-weight:bold;font-size:13px;color:#3b82f6');
  console.log('SHA-256 of message:', sha256);
  console.table({
    From: get('from')[0], 'Return-Path': get('return-path')[0], 'Reply-To': get('reply-to')[0],
    'Message-ID': get('message-id')[0], Subject: get('subject')[0], 'X-Mailer': get('x-mailer')[0],
  });

  console.log('%cReceived hops (newest → oldest):', 'font-weight:bold');
  get('received').forEach((h, i) => console.log(`  ${i + 1}. ${h}`));

  console.log('%cAuthentication-Results:', 'font-weight:bold', get('authentication-results'));
  console.log('DKIM signing domains (d=):',
    get('dkim-signature').map(s => (s.match(/\bd=([^;\s]+)/) || [])[1]));

  const body = raw.replace(/=\r?\n/g, '').replace(/=3D/gi, '=');
  const urls = [...new Set(body.match(/https?:\/\/[^\s"'<>)\]]+/g) || [])];
  console.log(`%cURLs (${urls.length}):`, 'font-weight:bold', urls);

  const atts = [...raw.matchAll(/filename\*?=(?:"([^"]+)"|([^;\r\n]+))/gi)].map(m => m[1] || m[2]);
  console.log('Attachments:', atts.length ? atts : 'none');

  window.__mailshark = { raw, sha256, headers };
  console.log('Full source kept in window.__mailshark.raw');
})();
