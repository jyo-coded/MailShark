// Preview-only WebExtension shim: lets the real background engine, popup, Lab and Gmail overlay run
// together in one ordinary web page for visual QA. Never shipped in the extension.
(() => {
  const L = { message: [], changed: [], installed: [], startup: [], alarm: [], permAdded: [], permRemoved: [] };
  const KEY = 'mailshark-preview-storage';
  let store = {};
  try {
    store = JSON.parse(localStorage.getItem(KEY) || '{}');
  } catch {
    store = {};
  }
  const persist = () => localStorage.setItem(KEY, JSON.stringify(store));
  const ev = (arr) => ({
    addListener: (f) => arr.push(f),
    removeListener: (f) => {
      const i = arr.indexOf(f);
      if (i >= 0) arr.splice(i, 1);
    },
    hasListener: (f) => arr.includes(f),
  });
  const clone = (v) => (v === undefined ? undefined : structuredClone(v));
  const sender = { id: 'mailshark@preview' };
  async function dispatch(msg) {
    for (const l of [...L.message]) {
      const r = l(clone(msg), sender);
      if (r !== undefined) return clone(await r);
    }
    return undefined;
  }
  window.browser = {
    runtime: {
      id: 'mailshark@preview',
      getURL: (p) => new URL(p.replace(/^\//, ''), location.origin + '/').href,
      sendMessage: dispatch,
      onMessage: ev(L.message),
      onInstalled: ev(L.installed),
      onStartup: ev(L.startup),
    },
    storage: {
      local: {
        async get(keys) {
          if (keys == null) return clone(store);
          const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
          const out = {};
          for (const k of list) if (k in store) out[k] = clone(store[k]);
          return out;
        },
        async set(obj) {
          const changes = {};
          for (const [k, v] of Object.entries(obj)) changes[k] = { oldValue: clone(store[k]), newValue: clone(v) };
          Object.assign(store, clone(obj));
          persist();
          for (const l of [...L.changed]) l(changes, 'local');
        },
      },
      onChanged: ev(L.changed),
    },
    tabs: {
      async query() {
        return [{ id: 1, url: window.__MS_TAB_URL__ || location.href }];
      },
      async create({ url }) {
        window.open(url, '_blank');
        return { id: 2 };
      },
      async sendMessage(_id, msg) {
        return dispatch(msg);
      },
    },
    alarms: { create() {}, async get() {}, onAlarm: ev(L.alarm) },
    permissions: {
      async contains() {
        return true;
      },
      async request() {
        return true;
      },
      onAdded: ev(L.permAdded),
      onRemoved: ev(L.permRemoved),
    },
  };
})();
