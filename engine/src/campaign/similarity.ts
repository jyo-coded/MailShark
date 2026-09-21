// Campaign similarity: "are these two e-mails manifestations of the same operation?"
// Layered, similarity-over-equality scoring; layers that are absent in both messages are skipped
// and the remaining weights renormalised, so a text-only lure isn't penalised for lacking files.
import type { Fingerprint } from '../types';
import { minhashSimilarity } from '../util/hash';
import { jaccard } from '../util/text';

export type Layer = 'content' | 'urls' | 'attachments' | 'infra' | 'sender' | 'semantic' | 'delivery';

export const LAYER_WEIGHTS: Record<Layer, number> = {
  content: 0.22,
  urls: 0.18,
  attachments: 0.15,
  infra: 0.17,
  sender: 0.1,
  semantic: 0.1,
  delivery: 0.08,
};

export const LAYER_LABELS: Record<Layer, string> = {
  content: 'Content & template',
  urls: 'Links & landing pages',
  attachments: 'Attachments',
  infra: 'Sending infrastructure',
  sender: 'Sender identity',
  semantic: 'Intent & brand',
  delivery: 'Delivery timing',
};

export interface Similarity {
  score: number;
  layers: Record<Layer, number | null>;
  hardLink: string | null;
}

function eq(a: string | null | undefined, b: string | null | undefined): number | null {
  if (!a || !b) return null;
  return a === b ? 1 : 0;
}

function weighted(parts: [number | null, number][]): number | null {
  let sum = 0;
  let w = 0;
  for (const [v, wt] of parts) {
    if (v === null) continue;
    sum += v * wt;
    w += wt;
  }
  return w ? sum / w : null;
}

export function similarity(a: Fingerprint, b: Fingerprint): Similarity {
  const subj = a.content.subjectTemplate && a.content.subjectTemplate === b.content.subjectTemplate ? 1 : (jaccard(a.content.subjectTokens, b.content.subjectTokens) ?? null);
  const mh = minhashSimilarity(a.content.minhash, b.content.minhash);
  const content = weighted([
    [mh, 0.5],
    [subj, 0.25],
    [eq(a.content.skeleton, b.content.skeleton), 0.2],
    [eq(a.content.classHash, b.content.classHash), 0.05],
  ]);

  const urlDom = jaccard(a.urls.domains, b.urls.domains);
  const urlTpl = jaccard(a.urls.templates, b.urls.templates);
  const urlPath = jaccard(a.urls.paths, b.urls.paths);
  const urls = urlDom === null && urlTpl === null ? null : Math.max(urlTpl ?? 0, (urlDom ?? 0) * 0.85, (urlPath ?? 0) * 0.8);

  let attachments: number | null = null;
  const anyAtt = a.attachments.sha256.length || b.attachments.sha256.length;
  if (anyAtt) {
    const shared = a.attachments.sha256.some((h) => b.attachments.sha256.includes(h));
    attachments = shared
      ? 1
      : Math.max((jaccard(a.attachments.structural, b.attachments.structural) ?? 0) * 0.85, (jaccard(a.attachments.nameTemplates, b.attachments.nameTemplates) ?? 0) * 0.5);
  }

  const infra = weighted([
    [eq(a.infra.originNet, b.infra.originNet), 0.2],
    [eq(a.infra.originOrg, b.infra.originOrg), 0.1],
    [eq(a.infra.xMailer, b.infra.xMailer), 0.15],
    [a.infra.dkimDomains.length || b.infra.dkimDomains.length ? (jaccard(a.infra.dkimDomains, b.infra.dkimDomains) ?? 0) : null, 0.15],
    [a.infra.dkimSelectors.length && b.infra.dkimSelectors.length ? (jaccard(a.infra.dkimSelectors, b.infra.dkimSelectors) ?? 0) : null, 0.05],
    [eq(a.infra.headerOrder, b.infra.headerOrder), 0.2],
    [eq(a.infra.messageIdTemplate, b.infra.messageIdTemplate), 0.1],
    [eq(a.infra.dkimHeaderSet, b.infra.dkimHeaderSet), 0.05],
  ]);

  const sender = weighted([
    [eq(a.sender.fromOrg, b.sender.fromOrg), 0.35],
    [eq(a.sender.localTemplate, b.sender.localTemplate), 0.15],
    [eq(a.sender.displayName, b.sender.displayName), 0.3],
    [eq(a.sender.replyToOrg, b.sender.replyToOrg), 0.2],
  ]);

  const semantic =
    a.content.intent || b.content.intent || a.content.brand || b.content.brand
      ? weighted([
          [eq(a.content.intent, b.content.intent), 0.5],
          [eq(a.content.brand, b.content.brand), 0.35],
          [a.content.actions.length || b.content.actions.length ? (jaccard(a.content.actions, b.content.actions) ?? 0) : null, 0.15],
        ])
      : null;

  const dtDays = Math.abs(a.time - b.time) / 86_400_000;
  const delivery = Number.isFinite(dtDays) && a.time > 0 && b.time > 0 ? Math.exp(-dtDays / 3) : null;

  const layers: Record<Layer, number | null> = { content, urls, attachments, infra, sender, semantic, delivery };
  let total = 0;
  let wsum = 0;
  for (const layer of Object.keys(LAYER_WEIGHTS) as Layer[]) {
    const v = layers[layer];
    if (v === null) continue;
    total += v * LAYER_WEIGHTS[layer];
    wsum += LAYER_WEIGHTS[layer];
  }
  let score = wsum ? total / wsum : 0;

  // Hard links: identifiers that practically prove a shared operation.
  let hardLink: string | null = null;
  if (a.infra.espCampaign && a.infra.espCampaign === b.infra.espCampaign) hardLink = 'Same bulk-mail campaign ID';
  else if (a.attachments.sha256.some((h) => b.attachments.sha256.includes(h))) hardLink = 'Identical attachment (SHA-256)';
  else if (mh >= 0.9 && (subj ?? 0) >= 0.8) hardLink = 'Near-identical message text';
  else if (a.urls.templates.length && urlTpl !== null && urlTpl >= 0.8 && mh >= 0.5) hardLink = 'Same landing-page URL pattern';
  if (hardLink) score = Math.max(score, 0.9);

  return { score: Math.round(score * 1000) / 1000, layers, hardLink };
}
