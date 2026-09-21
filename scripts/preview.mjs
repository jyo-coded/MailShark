// Local QA harness: builds a preview flavour of the extension and serves
//   /lab.html  /popup.html  /welcome.html   extension pages (engine running in-page)
//   /mail/u/0/                              a Gmail look-alike wired to the golden fixtures
// Gmail's raw-message endpoint (?view=att&th=<id>) is emulated with fixtures/eml/*.eml.
import http from 'node:http';
import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { buildExtension, root } from './build-lib.mjs';

const PORT = Number(process.env.PORT ?? 5178);
const out = join(root, 'dist', 'preview');
await buildExtension({ target: 'firefox', out, dev: true, preview: true });
writeFileSync(join(out, 'preview-shim.js'), readFileSync(join(root, 'scripts', 'preview', 'shim.js')));

// ── Fixtures ──
const fxDir = join(root, 'fixtures', 'eml');
const fixtures = existsSync(fxDir) ? readdirSync(fxDir).filter((f) => f.endsWith('.eml')).sort() : [];
const byId = new Map();
const rows = fixtures.map((file, i) => {
  const raw = readFileSync(join(fxDir, file), 'latin1');
  const head = raw.split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' ');
  const h = (k) => (new RegExp(`^${k}:\\s*(.*)$`, 'im').exec(head)?.[1] ?? '').trim();
  const id = `18f2a1c0de${(i + 1).toString(16).padStart(6, '0')}`;
  byId.set(id, raw);
  const from = h('From');
  const name = (/^"?([^"<]+)"?\s*</.exec(from)?.[1] ?? from).trim();
  const link = /href="(https?:[^"]+)"[^>]*>([^<]+)</.exec(raw.includes('Content-Transfer-Encoding: base64') ? decodeBodies(raw) : raw);
  return { id, file, subject: Buffer.from(h('Subject'), 'latin1').toString('utf8'), name, from, link: link ? { href: link[1], text: link[2] } : null };
});

function decodeBodies(raw) {
  return raw.replace(/Content-Transfer-Encoding: base64\r?\n\r?\n([A-Za-z0-9+/=\r\n]+)/g, (_, b64) => Buffer.from(b64.replace(/\s+/g, ''), 'base64').toString('utf8'));
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function gmailPage() {
  const data = JSON.stringify(rows.map((r) => ({ id: r.id, subject: r.subject, name: r.name, from: r.from, link: r.link })));
  return `<!doctype html><html><head><meta charset="utf-8"><title>Inbox – Gmail (MailShark preview)</title>
<style>
  body{margin:0;font:14px/1.45 Arial,Helvetica,sans-serif;background:#f6f8fc;color:#1f1f1f}
  .top{height:64px;display:flex;align-items:center;gap:16px;padding:0 16px}.logo{font:22px 'Product Sans',Arial;color:#444;width:220px}
  .search{flex:1;max-width:720px;height:46px;border-radius:24px;background:#e9eef6;display:flex;align-items:center;padding:0 20px;color:#555}
  .wrap{display:flex}.nav{width:240px;padding:8px 0}.nav div{padding:6px 24px;border-radius:0 16px 16px 0;margin-right:12px}.nav .on{background:#d3e3fd;font-weight:700}
  div[role=main].nH{flex:1;background:#fff;border-radius:16px;margin:0 16px 16px 0;min-height:calc(100vh - 80px);overflow:hidden}
  table{width:100%;border-collapse:collapse}tr.zA{cursor:pointer;border-bottom:1px solid #f1f1f1;height:40px}tr.zA:hover{box-shadow:inset 1px 0 #dadce0,inset -1px 0 #dadce0,0 1px 2px rgba(60,64,67,.3)}
  td{padding:0 12px;white-space:nowrap}td.yX{width:200px;font-weight:700}.xT{display:flex;align-items:center;overflow:hidden}.y6{font-weight:700;overflow:hidden;text-overflow:ellipsis}
  .thread{padding:20px 28px}h2.hP{font:400 22px 'Google Sans',Arial;margin:4px 0 20px}.gE{display:flex;gap:12px;align-items:center;margin-bottom:12px}.av{width:40px;height:40px;border-radius:50%;background:#7e57c2;color:#fff;display:grid;place-items:center}
  .a3s{font:14px/1.6 Arial;color:#222;max-width:760px}.back{cursor:pointer;color:#0b57d0;margin-bottom:10px;display:inline-block}
</style></head><body>
<div class="top"><div class="logo">Gmail <small style="font-size:12px;color:#888">preview</small></div><div class="search">Search mail</div></div>
<div class="wrap"><div class="nav"><div class="on">Inbox</div><div>Starred</div><div>Snoozed</div><div>Sent</div><div>Drafts</div></div>
<div class="nH bkK" role="main" id="main"></div></div>
<script>
window.__MS_TAB_URL__ = 'https://mail.google.com/mail/u/0/';
const DATA = ${data};
const main = document.getElementById('main');
function list(){
  main.innerHTML = '<table><tbody>' + DATA.map(m => '<tr class="zA zE" data-id="'+m.id+'"><td class="yX xY">'+esc(m.name)+'</td><td class="xY a4W"><div class="xS"><div class="xT"><div class="y6"><span class="bog"><span data-thread-id="#thread-f:'+m.id+'" data-legacy-thread-id="'+m.id+'" data-legacy-last-message-id="'+m.id+'">'+esc(m.subject)+'</span></span></div></div></div></td></tr>').join('') + '</tbody></table>';
  main.querySelectorAll('tr.zA').forEach(tr => tr.addEventListener('click', () => open(tr.dataset.id)));
}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c])}
function open(id){
  const m = DATA.find(x => x.id === id);
  const link = m.link ? '<p><a href="'+esc(m.link.href)+'" target="_blank" rel="noopener">'+esc(m.link.text)+'</a></p>' : '';
  main.innerHTML = '<div class="thread"><span class="back" id="back">← Back to inbox</span><h2 class="hP" data-thread-perm-id="thread-f:'+id+'" data-legacy-thread-id="'+id+'">'+esc(m.subject)+'</h2>'
    + '<div class="adn ads" data-message-id="#msg-f:'+id+'" data-legacy-message-id="'+id+'"><div class="gE iv gt"><div class="av">'+esc(m.name[0]||'?')+'</div><div><b>'+esc(m.name)+'</b><div style="color:#5e5e5e;font-size:12px">'+esc(m.from)+'</div></div></div>'
    + '<div class="ii gt"><div class="a3s aiL"><p>(Preview body: the original message is fetched from the emulated Gmail endpoint and dissected by MailShark.)</p>'+link+'</div></div></div></div>';
  document.getElementById('back').addEventListener('click', list);
}
const q = new URLSearchParams(location.search).get('open');
if (q) open(q); else list();
</script>
<script src="/preview-shim.js"></script><script src="/background.js"></script><script src="/content.js"></script>
</body></html>`;
}

function pageWithEngine(name, width) {
  const html = readFileSync(join(out, `${name}.html`), 'utf8');
  return html
    .replace('<script src="', '<script src="/preview-shim.js"></script><script src="/background.js"></script><script src="')
    .replace(/href="app\.css"/, 'href="/app.css"')
    .replace(/src="(\w+)\.js"/, 'src="/$1.js"')
    .replace('<body class="ms-page">', width ? `<body class="ms-page" style="width:${width}px">` : '<body class="ms-page">');
}

const TYPES = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json' };

http
  .createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
    if (url.pathname.startsWith('/mail/u/0')) {
      if (url.searchParams.get('view') === 'att') {
        const raw = byId.get(url.searchParams.get('th') ?? '');
        if (!raw) return res.writeHead(404).end('not found');
        res.writeHead(200, { 'content-type': 'message/rfc822' });
        return res.end(Buffer.from(raw, 'latin1'));
      }
      res.writeHead(200, { 'content-type': TYPES['.html'] });
      return res.end(gmailPage());
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'content-type': TYPES['.html'] });
      return res.end(`<!doctype html><meta charset="utf-8"><title>MailShark preview</title><body style="font:15px system-ui;padding:32px"><h1>MailShark preview</h1><ul>
        <li><a href="/mail/u/0/">Gmail mock (${rows.length} fixtures)</a></li><li><a href="/lab.html">Lab</a></li><li><a href="/popup.html">Popup</a></li><li><a href="/welcome.html">Welcome</a></li></ul>
        <p>Fixtures: ${rows.map((r) => `<a href="/mail/u/0/?open=${r.id}">${esc(r.file)}</a>`).join(' · ')}</p>`);
    }
    if (['/lab.html', '/popup.html', '/welcome.html'].includes(url.pathname)) {
      const name = url.pathname.slice(1, -5);
      res.writeHead(200, { 'content-type': TYPES['.html'] });
      return res.end(pageWithEngine(name, name === 'popup' ? 380 : 0));
    }
    const file = normalize(join(out, decodeURIComponent(url.pathname)));
    if (!file.startsWith(out) || !existsSync(file)) return res.writeHead(404).end('not found');
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(readFileSync(file));
  })
  .listen(PORT, () => console.log(`MailShark preview on http://localhost:${PORT}/  (${rows.length} fixtures)`));

