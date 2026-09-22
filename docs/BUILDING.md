# Building MailShark from source

These steps rebuild the exact files in the add-on package submitted to addons.mozilla.org. They are
written for Mozilla reviewers but work for anyone.

## Requirements

| Tool | Version |
|---|---|
| Operating system | Windows 10/11, macOS 13+ or Ubuntu 22.04+ (any OS that runs Node) |
| Node.js | 22.12 or newer (22 LTS tested: 22.19.0) |
| npm | 10 or newer (bundled with Node 22) |

No other tools, global packages or network services are needed besides the npm registry.

## Steps

```bash
npm ci
npm run build
```

- `npm ci` installs the exact dependency versions pinned in `package-lock.json`.
- `npm run build` (`node scripts/build.mjs`) writes the add-on to `dist/firefox/`. That folder has the same files, byte for byte, as the submitted package.

To also produce the zip and run addons-linter against it:

```bash
npm run package
```

## What the build does

`scripts/build-lib.mjs` does four things, and nothing is downloaded during the build:

1. Copies `extension/public/` (HTML pages and pre-rendered PNG icons) to `dist/firefox/`.
2. Copies three Geist font files (`.woff2`, SIL OFL 1.1) and their licences from `node_modules/@fontsource-variable/`.
3. Writes `manifest.json` from `extension/manifest.mjs`, using the version in `package.json`.
4. Bundles five entry points with esbuild into self-contained IIFE scripts:

| Output | Source entry |
|---|---|
| `background.js` | `extension/src/background/index.ts` |
| `content.js` | `extension/src/content/index.tsx` |
| `popup.js` | `extension/src/popup/main.tsx` |
| `lab.js` | `extension/src/lab/main.tsx` |
| `welcome.js` | `extension/src/welcome/main.tsx` |

The bundles are **not minified**: identifiers, formatting and comments are kept so they can be read directly.
- esbuild's `minifySyntax` is enabled only to remove dead branches, i.e. test-only code guarded by the `__MS_PREVIEW__` build constant, which is `false` in releases.
- A small esbuild plugin (`noInnerHtml` in `build-lib.mjs`) rewrites Preact's two `innerHTML` writes to `textContent`. The shipped code therefore contains no `innerHTML` assignments at all.
- `app.css` is the concatenation of `extension/src/ui/styles/{fonts,tokens,components,dissector,pages}.css`.

The icons in `extension/public/icons/` are committed PNGs. They were generated from the vector mark in `extension/brand/mark.mjs` by `npm run icons` (uses `@resvg/resvg-js`). Regenerating them is optional and does not change the output.

## Source layout

| Path | Contents |
|---|---|
| `engine/src/` | The analysis engine: MIME parsing, header, authentication and route forensics, link, HTML and attachment analysis, scoring and campaign fingerprints. Pure TypeScript, with no network access. |
| `extension/src/background/` | Event page: analysis pipeline, IndexedDB evidence store, campaign correlation, threat-feed updates, QR decoding. |
| `extension/src/content/` | Gmail integration: reads the opened message's raw source from Gmail's own "Show original" endpoint and renders the verdict banner and inspector in a closed shadow root. |
| `extension/src/lab/`, `popup/`, `welcome/` | Extension pages (Preact). |
| `extension/src/ui/` | Shared components, icons and design tokens. |

## Third-party code in the bundles

All of it comes from npm at the versions pinned in `package-lock.json`. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md):
- preact
- lucide-preact
- postal-mime
- tldts
- htmlparser2
- fflate
- jsQR
- idb
- d3-force
