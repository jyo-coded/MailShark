export * from './types';
export { analyzeEmail, ENGINE_VERSION } from './analyze';
export { buildFindings, scoreFindings, sortFindings, BIAS, DANGER_AT, CAUTION_AT } from './score';
export { similarity, LAYER_LABELS, LAYER_WEIGHTS, type Layer, type Similarity } from './campaign/similarity';
export { assignCampaign, profileCampaign, newCampaignId, JOIN_THRESHOLD, MERGE_THRESHOLD, type CampaignMember, type CampaignProfile, type Assignment, type AttributeSpread } from './campaign/cluster';
export { BloomFilter, BloomIntel, normalizeFeedHost, hostCandidates, type BloomMeta } from './intel/bloom';
export { toStixBundle, toIocCsv, toMarkdown } from './export';
export { brandById, BRANDS } from './data/brands';
