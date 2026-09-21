// HTML body forensics. The HTML is parsed into an inert tree (htmlparser2): never rendered, never
// executed, remote resources never fetched.
import { parseDocument } from 'htmlparser2';
import type { ChildNode, Element } from 'domhandler';
import type { HtmlAnalysis } from '../types';
import type { LinkCandidate } from './links';
import { hash53 } from '../util/hash';
import { hostInfo } from '../util/domain';
import { collapseWs, countZeroWidth } from '../util/text';

export interface HtmlResult {
  analysis: HtmlAnalysis;
  visibleText: string;
  hiddenText: string;
  links: LinkCandidate[];
  dataImages: { mime: string; base64: string }[];
}

const BLOCK = new Set(['p', 'div', 'br', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'section', 'article', 'header', 'footer', 'blockquote', 'hr', 'td', 'th', 'ul', 'ol', 'center']);
const SKIP_TEXT = new Set(['script', 'style', 'head', 'title', 'noscript', 'template', 'xml', 'svg']);
const SKELETON_TAGS = new Set(['table', 'tr', 'td', 'div', 'p', 'a', 'img', 'span', 'h1', 'h2', 'h3', 'ul', 'li', 'form', 'input', 'button', 'center', 'font', 'b', 'strong']);

function isHiddenStyle(style: string): boolean {
  const s = style.toLowerCase().replace(/\s+/g, '');
  return (
    /display:none/.test(s) ||
    /visibility:hidden/.test(s) ||
    /(^|;)font-size:0(px|pt|em|%)?(;|$|!)/.test(s) ||
    /(^|;)opacity:0(\.0+)?(;|$|!)/.test(s) ||
    /max-height:0(px)?(;|$|!)/.test(s) && /overflow:hidden/.test(s) ||
    /mso-hide:all/.test(s) ||
    /(^|;)(width|height):0(px)?(;|$|!)/.test(s) && /overflow:hidden/.test(s) ||
    /color:(#fff(fff)?|white|rgb\(255,255,255\))/.test(s) && /background(-color)?:(#fff(fff)?|white|rgb\(255,255,255\))/.test(s)
  );
}

function textOf(node: ChildNode): string {
  if (node.type === 'text') return (node as unknown as { data: string }).data;
  if ('children' in node && Array.isArray((node as Element).children)) return (node as Element).children.map(textOf).join(' ');
  return '';
}

export function analyzeHtml(html: string | undefined | null): HtmlResult {
  const empty: HtmlAnalysis = {
    present: false, tagCount: 0, skeletonHash: null, classHash: null, forms: [], scripts: 0, iframes: 0, embeds: 0,
    metaRefresh: null, baseHref: null, images: 0, remoteImageHosts: [], trackingPixels: 0, hiddenTextChars: 0,
    zeroWidthChars: 0, visibleTextChars: 0, imageOnly: false,
  };
  if (!html || !html.trim()) return { analysis: empty, visibleText: '', hiddenText: '', links: [], dataImages: [] };

  const doc = parseDocument(html.length > 2_000_000 ? html.slice(0, 2_000_000) : html, { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
  const a: HtmlAnalysis = { ...empty, present: true, forms: [], remoteImageHosts: [] };
  const visible: string[] = [];
  const hidden: string[] = [];
  const skeleton: string[] = [];
  const classes = new Set<string>();
  const links: LinkCandidate[] = [];
  const dataImages: { mime: string; base64: string }[] = [];
  const imageHosts = new Set<string>();
  let formCtx: HtmlAnalysis['forms'][number] | null = null;

  const walk = (nodes: ChildNode[], depth: number, hiddenCtx: boolean): void => {
    for (const node of nodes) {
      if (node.type === 'text') {
        const t = (node as unknown as { data: string }).data;
        if (t.trim()) (hiddenCtx ? hidden : visible).push(t);
        continue;
      }
      if (node.type !== 'tag' && node.type !== 'script' && node.type !== 'style') continue;
      const el = node as Element;
      const name = el.name.toLowerCase();
      const at = el.attribs ?? {};
      a.tagCount++;
      if (a.tagCount > 50_000) return;
      if (SKELETON_TAGS.has(name) && depth < 14 && skeleton.length < 4000) skeleton.push(`${depth}${name}`);
      if (at['class']) at['class'].split(/\s+/).filter(Boolean).slice(0, 8).forEach((c) => classes.add(c.toLowerCase()));

      switch (name) {
        case 'script':
          a.scripts++;
          if (at['src']) links.push({ url: at['src'], source: 'html-other' });
          break;
        case 'iframe':
        case 'frame':
          a.iframes++;
          if (at['src']) links.push({ url: at['src'], source: 'html-other' });
          break;
        case 'object':
        case 'embed':
        case 'applet':
          a.embeds++;
          break;
        case 'meta': {
          if ((at['http-equiv'] ?? '').toLowerCase() === 'refresh') {
            a.metaRefresh = at['content'] ?? '';
            const m = /url\s*=\s*['"]?([^'";]+)/i.exec(a.metaRefresh);
            if (m && m[1]) links.push({ url: m[1], source: 'html-other' });
          }
          break;
        }
        case 'base':
          a.baseHref = at['href'] ?? null;
          break;
        case 'a':
        case 'area':
          if (at['href']) links.push({ url: at['href'], source: 'html-anchor', text: collapseWs(textOf(el)) || at['title'] || null });
          break;
        case 'form':
          formCtx = { action: at['action'] ?? null, inputs: [], hasPassword: false };
          a.forms.push(formCtx);
          if (at['action']) links.push({ url: at['action'], source: 'html-form' });
          break;
        case 'input': {
          const type = (at['type'] ?? 'text').toLowerCase();
          const target = formCtx ?? (a.forms.length ? a.forms[a.forms.length - 1] : null);
          if (target) {
            target.inputs.push(`${type}:${at['name'] ?? at['id'] ?? ''}`);
            if (type === 'password') target.hasPassword = true;
          } else if (type === 'password' || type === 'email' || type === 'text') {
            a.forms.push({ action: null, inputs: [`${type}:${at['name'] ?? ''}`], hasPassword: type === 'password' });
          }
          break;
        }
        case 'img': {
          a.images++;
          const src = at['src'] ?? '';
          const w = at['width'] ?? '';
          const h = at['height'] ?? '';
          const style = (at['style'] ?? '').replace(/\s+/g, '').toLowerCase();
          if ((/^[01](px)?$/.test(w) && /^[01](px)?$/.test(h)) || /width:[01]px/.test(style) && /height:[01]px/.test(style)) a.trackingPixels++;
          const dm = /^data:(image\/[a-z+.-]+);base64,(.+)$/is.exec(src);
          if (dm) {
            if (dataImages.length < 8) dataImages.push({ mime: (dm[1] as string).toLowerCase(), base64: (dm[2] as string).replace(/\s+/g, '') });
          } else if (/^https?:/i.test(src)) {
            try {
              imageHosts.add(hostInfo(new URL(src).hostname).regDomain ?? new URL(src).hostname);
            } catch {
              /* ignore malformed */
            }
          }
          if (at['alt']) visible.push(at['alt']);
          break;
        }
        case 'link':
          if ((at['rel'] ?? '').toLowerCase().includes('stylesheet') && at['href']) links.push({ url: at['href'], source: 'html-other' });
          break;
      }

      if (SKIP_TEXT.has(name)) continue;
      const nowHidden = hiddenCtx || isHiddenStyle(at['style'] ?? '') || 'hidden' in at || (at['aria-hidden'] === 'true' && name !== 'img');
      if (BLOCK.has(name)) (nowHidden ? hidden : visible).push('\n');
      walk(el.children as ChildNode[], depth + 1, nowHidden);
      if (name === 'form') formCtx = null;
    }
  };
  walk(doc.children as ChildNode[], 0, false);

  const visibleText = visible.join(' ').replace(/[ \t ]+/g, ' ').replace(/\s*\n\s*/g, '\n').replace(/\n{2,}/g, '\n').trim();
  const hiddenText = collapseWs(hidden.join(' '));
  a.visibleTextChars = visibleText.replace(/\s+/g, '').length;
  a.hiddenTextChars = hiddenText.replace(/\s+/g, '').length;
  a.zeroWidthChars = countZeroWidth(visible.join(''));
  a.skeletonHash = skeleton.length >= 5 ? hash53(skeleton.join(',')) : null;
  a.classHash = classes.size >= 3 ? hash53([...classes].sort().join(' ')) : null;
  a.remoteImageHosts = [...imageHosts].slice(0, 20);
  a.imageOnly = a.images > 0 && a.visibleTextChars < 60;
  return { analysis: a, visibleText, hiddenText, links, dataImages };
}
