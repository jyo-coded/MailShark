import type { Stats } from '../shared/protocol';

export type Page = 'overview' | 'campaigns' | 'history' | 'analyze' | 'academy' | 'settings' | 'about';
export type Route = { page: Page; arg: string | null };

export const PAGES: Page[] = ['overview', 'campaigns', 'history', 'analyze', 'academy', 'settings', 'about'];

export function parseHash(): Route {
  const [page, arg] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: (PAGES as string[]).includes(page ?? '') ? (page as Page) : 'overview', arg: arg ? decodeURIComponent(arg) : null };
}

export function go(page: Page, arg?: string): void {
  location.hash = `#/${page}${arg ? '/' + encodeURIComponent(arg) : ''}`;
}

export interface LabContext {
  openReport: (id: string) => void;
  stats: Stats | null;
  refreshStats: () => void;
}
