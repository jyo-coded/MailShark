// Isolated UI hosts: each overlay lives in a closed shadow root with its own stylesheet, so Gmail's
// CSS can't reach in and ours can't leak out. Key events are stopped at the host so Gmail's
// keyboard shortcuts don't fire while the user types inside MailShark.
import tokens from '../ui/styles/tokens.css';
import components from '../ui/styles/components.css';
import dissector from '../ui/styles/dissector.css';
import content from '../ui/styles/content.css';
import { ext } from '../shared/ext';

const BASE_CSS = `${tokens}\n${components}\n${content}`;
const FULL_CSS = `${tokens}\n${components}\n${dissector}\n${content}`;

export interface Host {
  host: HTMLElement;
  root: HTMLElement; // .ms-root inside the shadow
  shadow: ShadowRoot;
}

export function createHost(kind: 'banner' | 'overlay' | 'badge', theme: 'dark' | 'light', tag: 'div' | 'span' = 'div'): Host {
  const host = document.createElement(tag);
  host.setAttribute('data-mailshark-host', kind);
  host.style.setProperty('all', 'initial');
  host.style.setProperty('display', kind === 'badge' ? 'inline-block' : 'block');
  const shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = kind === 'overlay' ? FULL_CSS : BASE_CSS;
  shadow.appendChild(style);
  const root = document.createElement(kind === 'badge' ? 'span' : 'div');
  root.className = 'ms-root';
  root.setAttribute('data-theme', theme);
  shadow.appendChild(root);
  if (kind !== 'badge') {
    for (const type of ['keydown', 'keyup', 'keypress'] as const) host.addEventListener(type, (e) => e.stopPropagation());
  }
  return { host, root, shadow };
}

let fontsInjected = false;

/** Register the bundled fonts on the page (fonts declared inside shadow roots are ignored by browsers). */
export function injectFonts(): void {
  if (fontsInjected) return;
  fontsInjected = true;
  const url = (f: string): string => ext.runtime.getURL(`fonts/${f}`);
  const style = document.createElement('style');
  style.setAttribute('data-mailshark-fonts', '');
  style.textContent = [
    `@font-face{font-family:'MS Geist';src:url('${url('geist-latin.woff2')}') format('woff2');font-weight:100 900;font-display:swap;unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+20AC,U+2122,U+2212,U+FEFF,U+FFFD;}`,
    `@font-face{font-family:'MS Geist';src:url('${url('geist-latin-ext.woff2')}') format('woff2');font-weight:100 900;font-display:swap;unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+1E00-1EFF,U+20A0-20AB,U+20AD-20C0,U+2C60-2C7F,U+A720-A7FF;}`,
    `@font-face{font-family:'MS Geist Mono';src:url('${url('geist-mono-latin.woff2')}') format('woff2');font-weight:100 900;font-display:swap;}`,
  ].join('\n');
  (document.head ?? document.documentElement).appendChild(style);
}
