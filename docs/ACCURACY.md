# Detection accuracy

MailShark's engine (`engine/src`) was measured on **16,228 real emails** from three public research corpora. The engine run here is the same code that ships in the add-on.

```bash
node scripts/eval/run.mjs                      # all corpora, writes lab/out/engine-eval.jsonl
node scripts/eval/run.mjs --intel <feeds/v1>   # with the threat-feed Bloom filters enabled
```

The corpora are not redistributed. See [lab/README.md](../lab/README.md#datasets) for download links.

## Corpora

| Corpus | Label | Messages | Notes |
|---|---|---|---|
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) 2015–2025 | phishing | 3,466 | Hand-collected phishing, CC BY 4.0 |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | phishing | 8,612 | Honeypot catch. It also contains large amounts of spam, casino and adult scams with no phishing intent. 3 samples were quarantined by antivirus and skipped. |
| [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/) easy_ham, easy_ham_2 | legitimate | 3,900 | Mailing lists, newsletters and personal mail |
| SpamAssassin hard_ham | legitimate | 250 | Legitimate mail that *looks* like spam or phishing (marketing, receipts, account notices) |

## Results (default "balanced" sensitivity)

"Flagged" means the verdict is *Suspicious* or *Dangerous*: MailShark shows a warning banner.

| Corpus | Flagged | Rated dangerous |
|---|---|---|
| Nazario 2015–2025 (all years) | **85.7%** | 72.5% |
| Nazario, per year | 81.1–92.1% | 66.8–82.2% |
| phishing_pot | 68.4% | 47.5% |
| SpamAssassin easy_ham (false positives) | **0.1%** | 0.0% |
| SpamAssassin easy_ham_2 (false positives) | **0.5%** | 0.3% |
| SpamAssassin hard_ham (false positives) | 12.0% | 2.8% |

**Across all 16,228 messages:**
- recall is **73.4%**
- the false-positive rate on legitimate mail is **0.96%**, and only **0.29%** of legitimate mail is rated *Dangerous*
- precision is **99.55%**

### Sensitivity setting

| Setting | Thresholds (danger / suspicious) | Phishing flagged | Legitimate flagged | Legitimate rated dangerous | Precision |
|---|---|---|---|---|---|
| Strict | 60 / 25 | 78.4% | 1.20% | 0.39% | 99.48% |
| **Balanced** (default) | 70 / 35 | 73.4% | 0.96% | 0.29% | 99.55% |
| Relaxed | 80 / 45 | 69.0% | 0.77% | 0.12% | 99.62% |

### Tuning set vs held-out messages

The detectors and weights were tuned by inspecting misses and false alarms in the **first 400 messages of each corpus**. The messages after those 400 were never looked at during tuning; they are the honest estimate of performance on unseen mail:

| Split | Phishing | Legitimate | Phishing flagged | Legitimate flagged (dangerous) | Precision |
|---|---|---|---|---|---|
| Tuning (first 400 per corpus) | 3,669 | 1,050 | 84.8% | 3.05% (0.67%) | 98.98% |
| **Held-out** | 8,409 | 3,100 | 68.3% | **0.26% (0.16%)** | **99.86%** |

- **Nazario:** held-out recall matches tuning recall (85.8% vs 85.7%), so the rules did not overfit.
- **phishing_pot:** held-out recall is lower (67.9%). Most misses are scams without a phishing hook, such as casino, dating, "you won" or SEO spam. MailShark deliberately does not treat these as phishing. Of the 2,722 phishing_pot messages MailShark misses, 2,327 (85%) show no phishing intent at all: no credential, payment, delivery, document or other lure.
- **Tuning false-positive rate:** the higher rate comes from hard_ham, whose 250 messages all fall within the tuning split. Those are legitimate messages chosen *because* they look like spam.

### Threat feeds

With the public threat feeds enabled (Phishing.Database + URLhaus, filtered against the Tranco top sites), recall on these historical corpora barely changes (73.4% → 73.7%). Most domains in 2015–2024 phishing are long dead and have left the active lists.

The feeds matter for *current* mail. They add no false positives beyond one case: a 2002 newsletter linking to `filterfine.com`, a domain that is listed as phishing today.

Before the popular-site filter was added to `feeds/build_feeds.py`, the feeds raised the ham false-positive rate from 1.0% to 1.4% (the ISP `iol.ie` and `angelfire.com` were listed). After the filter it is back to 1.0%.

## Speed

Median analysis time is **6.8 ms** per message (p95 29 ms, p99 87 ms). Measured in Node 22 on a laptop CPU, including MIME parsing, HTML and attachment inspection and scoring.

## Campaign tracing

Clustering is evaluated separately in the forensic lab. That evaluation uses synthetic campaigns in which the attacker rotates a growing set of indicators:

| Attacker rotates | Exact-IOC matching F1 | MailShark campaign correlation F1 |
|---|---|---|
| nothing | 0.997 | 1.000 |
| domain + sender + URL + IP | 0.542 | 1.000 |
| almost everything (+ subject, wording, repacked file) | 0.000 | 0.999 |
| everything (+ HTML template, mailer, kit path) | 0.000 | 0.163 (precision 1.0) |

On real data, the lab traced the 481 Nazario 2025 messages into 50 campaigns. See [lab/README.md](../lab/README.md#results).

## Limitations

- **Corpus age.** The corpora are public and partly old. SpamAssassin ham dates from 2002–2003, and modern legitimate mail uses more tracking redirects, ESPs and HTML forms. Real-world false-positive rates on 2026 mail may differ. The *hard_ham* numbers are the conservative bound.
- **Unit of analysis.** MailShark scores one message at a time. It does not know your contacts or your organisation's normal senders, beyond what it has seen locally.
- **Scope of "phishing".** Scams that ask for nothing (no link, no attachment, no reply-to-pay instruction) are often rated safe or low-risk on purpose.
