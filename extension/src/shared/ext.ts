// WebExtension API handle. Firefox exposes the promise-based `browser` namespace natively;
// Chromium (future target) exposes promise-returning `chrome` in MV3.
type Browser = typeof browser;

const g = globalThis as unknown as { browser?: Browser; chrome?: Browser };
export const ext: Browser = (g.browser ?? g.chrome) as Browser;

export const VERSION: string = typeof __MS_VERSION__ === 'string' ? __MS_VERSION__ : '0.0.0-dev';
