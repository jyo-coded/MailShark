# Third-party notices

MailShark is MIT-licensed (see [LICENSE](LICENSE)). The add-on bundles the following open-source components. Each keeps its own licence.

## Code bundled into the add-on

| Component | Version | Licence | Copyright / source |
|---|---|---|---|
| [Preact](https://github.com/preactjs/preact) | 10.29.8 | MIT | © 2015-present Jason Miller |
| [Lucide](https://github.com/lucide-icons/lucide) (`lucide-preact`) | 1.47.0 | ISC | © Lucide Icons and Contributors |
| [postal-mime](https://github.com/postalsys/postal-mime) | 3.0.0 | MIT-0 | © 2021-2025 Andris Reinman |
| [tldts](https://github.com/remusao/tldts) | 7.4.13 | MIT | © 2017 Thomas Parisot, 2018 Rémi Berson; includes the [Public Suffix List](https://publicsuffix.org) (MPL 2.0) |
| [htmlparser2](https://github.com/fb55/htmlparser2) | 12.0.0 | MIT | © 2010, 2011 Chris Winberry; Felix Böhm and contributors |
| [fflate](https://github.com/101arrowz/fflate) | 0.8.3 | MIT | © Arjun Barrett |
| [jsQR](https://github.com/cozmo/jsQR) | 1.4.0 | Apache-2.0 | © Cosmo Wolfe and contributors |
| [idb](https://github.com/jakearchibald/idb) | 8.0.3 | ISC | © 2016 Jake Archibald |
| [d3-force](https://github.com/d3/d3-force) | 3.0.0 | ISC | © 2010-2021 Mike Bostock |

## Fonts

| Font | Licence | Notes |
|---|---|---|
| [Geist and Geist Mono](https://github.com/vercel/geist-font) | SIL Open Font License 1.1 | © The Geist Project Authors. Packaged by [Fontsource](https://fontsource.org). The licence texts ship inside the add-on as `fonts/LICENSE-Geist.txt` and `fonts/LICENSE-GeistMono.txt`. |

## Threat-intelligence data (downloaded at runtime, not bundled)

When threat feeds are enabled, the add-on downloads compiled Bloom filters from this repository's `feeds` branch. They are built daily by `feeds/build_feeds.py` from:

| Source | Licence / terms |
|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (active phishing domains) | MIT |
| [URLhaus](https://urlhaus.abuse.ch) host file (abuse.ch) | [URLhaus terms of use](https://urlhaus.abuse.ch/api/) (CC0) |
| [Tranco](https://tranco-list.eu) ranking (used only to *remove* popular sites from the feeds) | Free for research and commercial use; Le Pochat et al., NDSS 2019 |

## Research datasets (evaluation only, never distributed)

The accuracy benchmark in [docs/ACCURACY.md](docs/ACCURACY.md) uses:
- the [Nazario phishing corpus](https://monkey.org/~jose/phishing/) (CC BY 4.0, © Jose Nazario)
- the [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)
- [phishing_pot](https://github.com/rf-peixoto/phishing_pot)

None of this data is included in the repository or the add-on.
