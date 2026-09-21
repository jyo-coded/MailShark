// Generates manifest.json per browser target. Firefox is the primary target (MV3, event page).

export const EXTENSION_ID = 'mailshark@jyo-coded.github.io';

export function buildManifest({ version, target = 'firefox' }) {
  const base = {
    manifest_version: 3,
    name: 'MailShark: Phishing Forensics for Gmail',
    short_name: 'MailShark',
    version,
    description:
      'Dissects every email you open in Gmail on your device: sender forensics, link and attachment analysis, campaign tracing. Nothing leaves your browser.',
    homepage_url: 'https://github.com/jyo-coded/MailShark',
    icons: { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 96: 'icons/icon-96.png', 128: 'icons/icon-128.png' },
    action: {
      default_title: 'MailShark',
      default_popup: 'popup.html',
      default_icon: { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png' },
    },
    permissions: ['storage', 'unlimitedStorage', 'alarms'],
    host_permissions: ['https://mail.google.com/*'],
    content_scripts: [
      {
        matches: ['https://mail.google.com/*'],
        js: ['content.js'],
        run_at: 'document_idle',
        all_frames: false,
      },
    ],
    options_ui: { page: 'lab.html', open_in_tab: true },
    web_accessible_resources: [
      {
        resources: ['fonts/*.woff2'],
        matches: ['https://mail.google.com/*'],
      },
    ],
  };

  if (target === 'firefox') {
    return {
      ...base,
      background: { scripts: ['background.js'] },
      browser_specific_settings: {
        gecko: {
          id: EXTENSION_ID,
          strict_min_version: '140.0',
          data_collection_permissions: { required: ['none'] },
        },
        gecko_android: {
          strict_min_version: '142.0',
        },
      },
    };
  }
  // Chromium (future target; built only on request).
  return {
    ...base,
    background: { service_worker: 'background.js' },
    minimum_chrome_version: '120',
  };
}
