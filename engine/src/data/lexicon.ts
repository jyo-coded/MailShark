// Social-engineering lexicon. Phrases are matched on normalized text (lowercase, accents and
// zero-width characters stripped). Each intent maps to a phishing playbook from the APWG /
// Verizon DBIR taxonomies; weights express how specific a phrase is to that playbook.

export interface IntentDef {
  id: string;
  label: string;
  /** [phrase, weight] */
  phrases: [string, number][];
  action?: string;
}

export const INTENTS: IntentDef[] = [
  {
    id: 'credential', label: 'Credential harvesting', action: 'sign in via link',
    phrases: [
      ['verify your account', 3], ['verify your identity', 3], ['confirm your identity', 3], ['confirm your account', 3], ['validate your account', 3],
      ['update your password', 2], ['password expires', 3], ['password will expire', 3], ['your password has expired', 3], ['reset your password', 1.5],
      ['sign in to', 1], ['log in to', 1], ['login to your', 1.5], ['re-activate', 2], ['reactivate your', 2], ['unlock your account', 3],
      ['mailbox is full', 3], ['mailbox storage', 3], ['storage quota', 2.5], ['quota exceeded', 3], ['email account will be', 3], ['webmail', 2],
      ['keep your password', 3], ['keep same password', 3], ['security check', 1.5], ['verify your email', 1.5], ['credentials', 2],
      ['sign-in attempt', 1.5], ['unusual sign-in', 2], ['incomplete account', 2], ['account verification', 2.5], ['restore access', 2.5],
      ['click here to verify', 3], ['click below to verify', 3], ['secure your account', 2], ['login details', 2.5], ['upgrade your mailbox', 3],
      ['pending messages', 2.5], ['undelivered messages', 2.5], ['messages are on hold', 3], ['release your messages', 3],
    ],
  },
  {
    id: 'payment', label: 'Payment / invoice fraud', action: 'pay or change bank details',
    phrases: [
      ['wire transfer', 2.5], ['bank details', 2], ['banking details', 2], ['change of bank', 3], ['new bank account', 3], ['updated bank', 3],
      ['account details have changed', 3], ['outstanding invoice', 2.5], ['overdue invoice', 2.5], ['payment overdue', 2.5], ['past due', 1.5],
      ['remittance', 2], ['swift', 1.5], ['iban', 2], ['routing number', 2], ['proforma invoice', 2], ['payment advice', 2.5], ['invoice attached', 2],
      ['pay now', 1.5], ['payment failed', 2], ['payment declined', 2], ['card declined', 2], ['update your payment', 2.5], ['billing information', 2],
      ['update your billing', 2.5], ['subscription has been suspended', 3], ['renew your subscription', 1.5], ['purchase order', 1.5], ['settle the payment', 2.5],
    ],
  },
  {
    id: 'giftcard', label: 'Gift-card scam', action: 'buy gift cards',
    phrases: [['gift card', 2.5], ['gift cards', 2.5], ['itunes card', 3], ['google play card', 3], ['steam card', 3], ['scratch the back', 3], ['send me the codes', 3], ['are you available', 1.5], ['quick favor', 2], ['i need a favor', 2]],
  },
  {
    id: 'crypto', label: 'Crypto theft', action: 'connect wallet or share seed',
    phrases: [['seed phrase', 3.5], ['recovery phrase', 3.5], ['secret phrase', 3], ['private key', 2.5], ['connect your wallet', 3], ['wallet validation', 3], ['claim your tokens', 3], ['airdrop', 2], ['usdt', 1.5], ['bitcoin', 1], ['metamask', 1.5], ['synchronize your wallet', 3]],
  },
  {
    id: 'mfa', label: 'MFA / device-code theft', action: 'enter or share a code',
    phrases: [['devicelogin', 3.5], ['device code', 3], ['enter the code', 2], ['enter this code', 2], ['approve the sign-in', 2.5], ['approve the request', 2], ['share the code', 3], ['one-time code', 1.5], ['verification code', 1], ['otp', 1], ['authenticator app', 1.5]],
  },
  {
    id: 'delivery', label: 'Delivery scam', action: 'pay a fee or reschedule',
    phrases: [['delivery failed', 3], ['failed delivery', 3], ['unable to deliver', 3], ['could not be delivered', 2.5], ['customs fee', 3], ['redelivery', 2.5], ['reschedule delivery', 2.5], ['shipping fee', 2], ['package is on hold', 3], ['parcel is on hold', 3], ['held at', 1.5], ['tracking number', 1], ['your package', 1], ['your parcel', 1.5], ['address incomplete', 3], ['confirm your address', 2]],
  },
  {
    id: 'document', label: 'Fake shared document', action: 'open a shared file',
    phrases: [['shared a document', 2.5], ['shared a file', 2.5], ['has shared', 1.5], ['view document', 2], ['review document', 2], ['review and sign', 2], ['please review and sign', 2.5], ['e-signature', 1.5], ['secure message', 2], ['encrypted message', 2], ['voicemail', 2], ['voice message', 2], ['fax', 1.5], ['sent you a file', 2.5], ['document is ready', 2], ['access the document', 2.5], ['open the document', 2], ['scan document', 1.5]],
  },
  {
    id: 'tax', label: 'Tax / government lure', action: 'claim a refund',
    phrases: [['tax refund', 3], ['income tax refund', 3.5], ['refund of', 1.5], ['tax return', 1.5], ['eligible for a refund', 3], ['kyc', 2], ['update your kyc', 3.5], ['kyc verification', 3], ['pan card', 2], ['aadhaar', 1.5], ['gst', 1], ['stimulus', 2], ['tax notice', 2.5], ['penalty', 1.5], ['legal action', 2.5], ['arrest warrant', 3.5]],
  },
  {
    id: 'job', label: 'Job / task scam', action: 'pay a fee or share details',
    phrases: [['work from home', 2], ['part-time job', 2.5], ['part time job', 2.5], ['daily income', 3], ['earn up to', 2], ['per day', 1], ['registration fee', 3], ['security deposit', 2.5], ['task-based', 3], ['online tasks', 2.5], ['no experience needed', 2], ['no experience required', 2], ['whatsapp us', 2.5], ['telegram', 1.5], ['hr manager', 1], ['you have been shortlisted', 2], ['offer letter', 1.5], ['joining fee', 3.5], ['training fee', 3]],
  },
  {
    id: 'reward', label: 'Prize / reward lure', action: 'claim a prize',
    phrases: [['you have won', 3], ["you've won", 3], ['you are a winner', 3], ['lottery', 3], ['prize', 1.5], ['claim your reward', 3], ['claim your prize', 3], ['cash prize', 3], ['lucky draw', 3], ['congratulations', 1], ['selected to receive', 2.5], ['free gift', 2], ['reward points', 1.5], ['points will expire', 2.5], ['exclusive reward', 2], ['cashback', 1]],
  },
  {
    id: 'extortion', label: 'Extortion / sextortion', action: 'pay a ransom',
    phrases: [['i have access to your', 3], ['recorded you', 3.5], ['your webcam', 3], ['hacked your', 3], ['bitcoin address', 3], ['btc address', 3], ['pay within', 2.5], ['48 hours to pay', 3.5], ['compromising', 2], ['your contacts will', 3], ['i know your password', 3.5]],
  },
  {
    id: 'callback', label: 'Call-back (TOAD) scam', action: 'call a phone number',
    phrases: [['call us at', 2], ['call our', 1.5], ['helpline', 1.5], ['toll free', 1.5], ['toll-free', 1.5], ['if you did not authorize', 2.5], ["if you didn't authorize", 2.5], ['did not make this purchase', 3], ['cancel your subscription', 1.5], ['auto-renewal', 2], ['has been renewed', 2], ['order has been placed', 2], ['to cancel', 1], ['billing department', 2], ['refund department', 3]],
  },
  {
    id: 'bec', label: 'CEO / business email compromise', action: 'reply and act discreetly',
    phrases: [['are you at your desk', 3], ['are you available', 1.5], ['i need you to', 1.5], ['confidential', 1], ['keep this between us', 3], ['do not discuss', 2.5], ['urgent task', 2.5], ['i am in a meeting', 2.5], ["i'm in a meeting", 2.5], ['reply with your', 2], ['send me your', 1.5], ['your cell number', 2.5], ['whatsapp number', 2.5]],
  },
];

export const URGENCY: [string, number][] = [
  ['immediately', 1], ['urgent', 1], ['urgently', 1], ['action required', 1.5], ['immediate action', 1.5], ['final notice', 2], ['final warning', 2], ['last warning', 2],
  ['within 24 hours', 2], ['within 48 hours', 1.5], ['within 12 hours', 2], ['24 hours', 1], ['expires today', 2], ['expire today', 2], ['as soon as possible', 1],
  ['limited time', 1], ['act now', 1.5], ['right away', 1], ['failure to', 1.5], ['will be suspended', 2], ['will be terminated', 2], ['will be deleted', 2],
  ['will be closed', 2], ['will be locked', 2], ['will be disabled', 2], ['permanently', 1], ['deactivated', 1.5], ['suspended', 1.5], ['restricted', 1],
  ['unusual activity', 1.5], ['suspicious activity', 1.5], ['unauthorized', 1.5], ['compromised', 1.5], ['security alert', 1.5], ['locked', 1], ['time sensitive', 1.5],
  ['respond now', 1.5], ['do not ignore', 2], ['last chance', 1.5], ['today only', 1], ['before it is too late', 2],
];

export const GENERIC_GREETINGS = [
  'dear customer', 'dear user', 'dear valued', 'dear account holder', 'dear client', 'dear member', 'hello user', 'dear sir/madam',
  'dear sir or madam', 'dear beneficiary', 'dear friend', 'dear email user', 'dear webmail user', 'dear subscriber', 'valued customer',
  'dear applicant', 'dear candidate', 'dear student', 'attention:', 'dear recipient',
];

export const ATTACHMENT_INSTRUCTIONS: [string, number][] = [
  ['open the attached', 2], ['see attached', 1], ['find attached', 1], ['download the attachment', 2], ['enable content', 3], ['enable editing', 3],
  ['enable macros', 3.5], ['password is', 2.5], ['password:', 2], ['the password to open', 3], ['scan the qr', 3], ['scan qr code', 3], ['scan the code', 2.5],
];

/** Common English function words for a lightweight language guess. */
export const EN_STOPWORDS = new Set([
  'the', 'and', 'you', 'your', 'to', 'of', 'a', 'in', 'is', 'for', 'on', 'that', 'this', 'with', 'be', 'are', 'we', 'it', 'as', 'have', 'our',
  'will', 'please', 'from', 'by', 'at', 'or', 'an', 'if', 'not', 'can', 'has', 'been', 'was', 'any', 'all', 'more', 'account', 'thank',
]);
