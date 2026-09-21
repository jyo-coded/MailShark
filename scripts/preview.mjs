// Local QA harness: builds a preview flavour of the extension and serves
//   /lab.html  /popup.html  /welcome.html   extension pages (engine running in-page)
//   /mail/u/0/                              a Gmail look-alike wired to the golden fixtures
// Gmail's raw-message endpoint (?view=att&th=<id>) is emulated with fixtures/eml/*.eml.
import http from 'node:http';
import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { Parser } from 'htmlparser2';
import PostalMime from 'postal-mime';
import { buildExtension, root } from './build-lib.mjs';

const PORT = Number(process.env.PORT ?? 5178);
const out = join(root, 'dist', 'preview');
await buildExtension({ target: 'firefox', out, dev: true, preview: true });
writeFileSync(join(out, 'preview-shim.js'), readFileSync(join(root, 'scripts', 'preview', 'shim.js')));

// ── Fixtures ──
const fxDir = join(root, 'fixtures', 'eml');
const fixtures = existsSync(fxDir) ? readdirSync(fxDir).filter((f) => f.endsWith('.eml')).sort() : [];
const byId = new Map();
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

// Renders a fixture's body the way Gmail would show it, reduced to safe markup: paragraphs, lists,
// emphasis and links. Scripts, styles, forms and images never reach the mock page.
const KEEP = new Set(['p', 'br', 'b', 'strong', 'i', 'em', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'a']);
const BLOCK = new Set(['div', 'table', 'tr', 'section', 'header', 'footer', 'center', 'blockquote']);
const DROP = new Set(['script', 'style', 'head', 'title', 'form', 'select', 'textarea', 'button', 'noscript', 'template']);
function safeBody(mail) {
  if (!mail.html) return (mail.text ?? '').split(/\n{2,}/).filter((t) => t.trim()).map((t) => `<p>${esc(t.trim()).replace(/\n/g, '<br>')}</p>`).join('');
  let html = '';
  let skip = 0;
  const parser = new Parser(
    {
      onopentag(name, attrs) {
        if (DROP.has(name)) skip++;
        if (skip) return;
        if (name === 'img') html += `<span class="img">[image${attrs.alt ? `: ${esc(attrs.alt)}` : ''}]</span>`;
        else if (name === 'a') html += /^https?:/i.test(attrs.href ?? '') ? `<a href="${esc(attrs.href)}" target="_blank" rel="noopener">` : '<a>';
        else if (KEEP.has(name)) html += `<${name}>`;
        else if (BLOCK.has(name)) html += '<br>';
      },
      ontext(text) {
        if (!skip) html += esc(text);
      },
      onclosetag(name) {
        if (DROP.has(name)) skip = Math.max(0, skip - 1);
        else if (!skip && KEEP.has(name) && name !== 'br') html += `</${name}>`;
      },
    },
    { decodeEntities: true },
  );
  parser.write(mail.html);
  parser.end();
  return html.replace(/(<br>\s*){3,}/g, '<br><br>');
}

const rows = await Promise.all(
  fixtures.map(async (file, i) => {
    const bytes = readFileSync(join(fxDir, file));
    const raw = bytes.toString('latin1');
    const mail = await PostalMime.parse(bytes);
    const id = `18f2a1c0de${(i + 1).toString(16).padStart(6, '0')}`;
    byId.set(id, raw);
    const from = mail.from?.address ? `${mail.from.name ? `"${mail.from.name}" ` : ''}<${mail.from.address}>` : '';
    const name = mail.from?.name || mail.from?.address || '(no sender)';
    const files = mail.attachments.filter((a) => a.disposition !== 'inline').map((a) => a.filename ?? 'attachment');
    return { id, file, subject: mail.subject ?? '(no subject)', name, from, body: safeBody(mail), files };
  }),
);

function gmailPage(real = false) {
  const data = JSON.stringify(rows.map((r) => ({ id: r.id, subject: r.subject, name: r.name, from: r.from, body: r.body, files: r.files })));
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
  .a3s{font:14px/1.6 Arial;color:#222;max-width:760px}.a3s p{margin:0 0 12px}.a3s .img{color:#888}.att{display:inline-flex;gap:8px;align-items:center;border:1px solid #dadce0;border-radius:8px;padding:8px 12px;margin:8px 8px 0 0;font-size:13px;color:#444}.back{cursor:pointer;color:#0b57d0;margin-bottom:10px;display:inline-block}
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
  const files = m.files.map(f => '<span class="att">📎 '+esc(f)+'</span>').join('');
  main.innerHTML = '<div class="thread"><span class="back" id="back">← Back to inbox</span><h2 class="hP" data-thread-perm-id="thread-f:'+id+'" data-legacy-thread-id="'+id+'">'+esc(m.subject)+'</h2>'
    + '<div class="adn ads" data-message-id="#msg-f:'+id+'" data-legacy-message-id="'+id+'"><div class="gE iv gt"><div class="av">'+esc(m.name[0]||'?')+'</div><div><b>'+esc(m.name)+'</b><div style="color:#5e5e5e;font-size:12px">'+esc(m.from)+'</div></div></div>'
    + '<div class="ii gt"><div class="a3s aiL">'+m.body+'</div>'+(files ? '<div>'+files+'</div>' : '')+'</div></div></div>';
  document.getElementById('back').addEventListener('click', list);
}
const q = new URLSearchParams(location.search).get('open');
if (q) open(q); else list();
</script>
${real ? '' : '<script src="/preview-shim.js"></script><script src="/background.js"></script><script src="/content.js"></script>'}
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
      // ?real=1 serves the bare mock so a real installed extension (not the in-page shim) drives it.
      return res.end(gmailPage(url.searchParams.get('real') === '1'));
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

