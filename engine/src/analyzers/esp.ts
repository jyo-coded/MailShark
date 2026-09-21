// Email Service Provider (bulk sender) detection. ESPs embed customer & campaign identifiers in
// VERP bounce addresses and custom headers: an attacker-proof campaign fingerprint when present.
import type { EspInfo } from '../types';
import type { RawHeader } from '../mime/raw';
import { firstHeader } from '../mime/raw';
import { orgDomain } from '../util/domain';

interface EspRule {
  id: string;
  name: string;
  headers?: string[]; // presence of any of these headers
  mailer?: RegExp; // X-Mailer / X-Sender-Software
  hostOrgs?: string[]; // Received / Return-Path / DKIM org domains
  campaign?: (h: RawHeader[], returnPath: string) => { campaignId?: string | null; customerId?: string | null };
}

const hv = (h: RawHeader[], k: string): string => firstHeader(h, k) ?? '';

const RULES: EspRule[] = [
  {
    id: 'mailchimp', name: 'Mailchimp', headers: ['x-mc-user', 'x-mailchimp-campaign'], hostOrgs: ['mcsv.net', 'mcdlv.net', 'rsgsv.net', 'mailchimpapp.net', 'mandrillapp.com'],
    campaign: (h) => ({ campaignId: hv(h, 'x-campaignid') || hv(h, 'x-mailchimp-campaign') || null, customerId: hv(h, 'x-mc-user') || null }),
  },
  { id: 'sendgrid', name: 'Twilio SendGrid', headers: ['x-sg-eid', 'x-sg-id'], hostOrgs: ['sendgrid.net', 'sendgrid.com'] },
  { id: 'amazonses', name: 'Amazon SES', headers: ['x-ses-outgoing'], hostOrgs: ['amazonses.com'], campaign: (h) => ({ campaignId: /^[^:]*:[^:]*:([^:]+)/.exec(hv(h, 'feedback-id'))?.[1] ?? null }) },
  { id: 'mailgun', name: 'Mailgun', headers: ['x-mailgun-sid', 'x-mailgun-tag'], hostOrgs: ['mailgun.org', 'mailgun.net', 'mailgun.info'], campaign: (h) => ({ campaignId: hv(h, 'x-mailgun-tag') || null, customerId: hv(h, 'x-mailgun-sid') || null }) },
  { id: 'sparkpost', name: 'SparkPost', headers: ['x-msfbl'], hostOrgs: ['sparkpostmail.com', 'sparkpost.com'] },
  { id: 'postmark', name: 'Postmark', headers: ['x-pm-message-id', 'x-pm-tag'], hostOrgs: ['mtasv.net', 'postmarkapp.com'], campaign: (h) => ({ campaignId: hv(h, 'x-pm-tag') || null }) },
  { id: 'brevo', name: 'Brevo (Sendinblue)', headers: ['x-sib-id', 'x-mailin-campaign', 'x-mailin-client'], hostOrgs: ['sendinblue.com', 'brevo.com', 'sendibm1.com', 'sendibt2.com', 'sendibt3.com', 'sendibw.com'], campaign: (h) => ({ campaignId: hv(h, 'x-mailin-campaign') || null, customerId: hv(h, 'x-mailin-client') || null }) },
  { id: 'mailjet', name: 'Mailjet', headers: ['x-mj-mid', 'x-mailjet-campaign'], hostOrgs: ['mailjet.com', 'mjt.lu'], campaign: (h) => ({ campaignId: hv(h, 'x-mailjet-campaign') || null }) },
  { id: 'constantcontact', name: 'Constant Contact', headers: ['x-roving-id', 'x-roving-campaignid'], hostOrgs: ['constantcontact.com', 'ccsend.com', 'rs6.net', 'ctctcdn.com'], campaign: (h) => ({ campaignId: hv(h, 'x-roving-campaignid') || null, customerId: hv(h, 'x-roving-id') || null }) },
  { id: 'hubspot', name: 'HubSpot', headers: ['x-hs-cid'], hostOrgs: ['hubspotemail.net', 'hubspot.com', 'hs-mail.com'], campaign: (h) => ({ campaignId: hv(h, 'x-hs-cid') || null }) },
  { id: 'salesforcemc', name: 'Salesforce Marketing Cloud', headers: ['x-sfmc-stack', 'x-job'], hostOrgs: ['exacttarget.com', 'exct.net', 'sfmc-content.com', 'marketingcloudapps.com'], campaign: (h) => ({ campaignId: hv(h, 'x-job') || null }) },
  { id: 'klaviyo', name: 'Klaviyo', headers: ['x-kmail-account', 'x-kmail-message'], hostOrgs: ['klaviyomail.com', 'klaviyo.com', 'klaviyodns.com'], campaign: (h) => ({ customerId: hv(h, 'x-kmail-account') || null }) },
  { id: 'marketo', name: 'Adobe Marketo', headers: ['x-mktomailid', 'x-mkto-mailingid'], hostOrgs: ['mktomail.com', 'marketo.org', 'mktdns.com'], campaign: (h) => ({ campaignId: hv(h, 'x-mktomailid') || hv(h, 'x-mkto-mailingid') || null }) },
  { id: 'zohocampaigns', name: 'Zoho Campaigns', headers: ['x-zcm-rid'], hostOrgs: ['zcsend.net', 'zohocampaigns.com', 'maillist-manage.com'] },
  { id: 'mailerlite', name: 'MailerLite', headers: ['x-ml-mid'], hostOrgs: ['mlsend.com', 'mlsend2.com', 'mailerlite.com'] },
  { id: 'mailercloud', name: 'Mailercloud', mailer: /mailercloud/i, hostOrgs: ['mailercloud.com', 'mlrctk.com'] },
  { id: 'campaignmonitor', name: 'Campaign Monitor', headers: ['x-cmae-message'], hostOrgs: ['createsend.com', 'cmail19.com', 'cmail20.com', 'cmail1.com', 'cmail2.com'] },
  { id: 'aweber', name: 'AWeber', hostOrgs: ['aweber.com', 'aweber.net'] },
  { id: 'getresponse', name: 'GetResponse', hostOrgs: ['getresponse.com', 'gr-mail.com'] },
  { id: 'activecampaign', name: 'ActiveCampaign', hostOrgs: ['acems1.com', 'acems2.com', 'acemsa1.com', 'emsd1.com', 'activehosted.com'] },
  { id: 'customerio', name: 'Customer.io', hostOrgs: ['customeriomail.com', 'customer.io'] },
  { id: 'iterable', name: 'Iterable', hostOrgs: ['iterable.com', 'itbl.co'] },
  { id: 'braze', name: 'Braze', hostOrgs: ['braze.com', 'appboy.com'] },
  { id: 'netcore', name: 'Netcore', hostOrgs: ['netcorecloud.net', 'pepipost.net', 'netcoresmartech.com'] },
  { id: 'phpmailer', name: 'PHPMailer (script)', mailer: /phpmailer/i },
  { id: 'gammadyne', name: 'Gammadyne Mailer', mailer: /gammadyne/i },
  { id: 'sendblaster', name: 'SendBlaster', mailer: /sendblaster/i },
];

/**
 * VERP / bounce-address campaign extraction. ESPs encode identifiers as long runs of
 * numbers in the envelope sender, e.g. bounce.cli26174-1634010-…@mlrctk.com → customer 26174,
 * campaign 1634010.
 */
function verpIds(returnPath: string): { customerId: string | null; campaignId: string | null } {
  const local = returnPath.replace(/^<|>$/g, '').split('@')[0] ?? '';
  const cli = /(?:cli|client|cust|c)[._-]?(\d{3,})[-._](\d{4,})/i.exec(local);
  if (cli) return { customerId: cli[1] ?? null, campaignId: cli[2] ?? null };
  const nums = local.match(/\d{5,}/g);
  if (nums && nums.length >= 2) return { customerId: null, campaignId: nums[0] ?? null };
  return { customerId: null, campaignId: null };
}

export function detectEsp(headers: RawHeader[], hostHints: string[], returnPath: string): EspInfo | null {
  const keys = new Set(headers.map((h) => h.key));
  const mailer = (firstHeader(headers, 'x-mailer') ?? firstHeader(headers, 'x-sender-software') ?? '').trim();
  const orgs = new Set(hostHints.map((h) => orgDomain(h)).filter(Boolean));

  for (const rule of RULES) {
    let evidence: string | null = null;
    const header = rule.headers?.find((k) => keys.has(k));
    if (header) evidence = `header ${header}`;
    else if (rule.mailer && rule.mailer.test(mailer)) evidence = `X-Mailer: ${mailer}`;
    else {
      const org = rule.hostOrgs?.find((o) => orgs.has(o));
      if (org) evidence = `infrastructure ${org}`;
    }
    if (!evidence) continue;
    const fromRule = rule.campaign?.(headers, returnPath) ?? {};
    const verp = verpIds(returnPath);
    return {
      id: rule.id,
      name: rule.name,
      campaignId: fromRule.campaignId || verp.campaignId || null,
      customerId: fromRule.customerId || verp.customerId || null,
      evidence,
    };
  }
  // Unknown bulk sender: List-Unsubscribe + Precedence/Feedback-ID and a VERP address.
  if (keys.has('list-unsubscribe') && (keys.has('feedback-id') || /bulk|list/i.test(firstHeader(headers, 'precedence') ?? ''))) {
    const verp = verpIds(returnPath);
    return { id: 'bulk', name: 'Bulk mailer', campaignId: verp.campaignId, customerId: verp.customerId, evidence: 'List-Unsubscribe + bulk headers' };
  }
  return null;
}
