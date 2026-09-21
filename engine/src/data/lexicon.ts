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
      // IT-administrator / mailbox lures (the most common family in the Nazario corpus).
      ['password expiry', 3], ['password expiration', 3], ['expired password', 3], ['password reset required', 3], ['change your password', 1.5],
      ['quota', 1.5], ['storage full', 3], ['mailbox full', 3], ['over the storage limit', 3], ['exceeded the storage', 3], ['exceeded its storage', 3],
      ['upgrade your account', 2.5], ['mailbox upgrade', 3], ['email upgrade', 3], ['account upgrade', 2.5], ['upgrade now', 1.5],
      ['account deactivation', 3], ['deactivation', 2], ['email suspension', 3], ['account suspension', 2.5], ['will be deactivated', 2.5],
      ['undelivered mails', 3], ['undelivered emails', 3], ['pending mails', 3], ['pending emails', 3], ['incoming messages', 2], ['held messages', 3],
      ['messages failed to deliver', 3], ['failed to deliver', 1.5], ['email verification', 2], ['e-mail verification', 2], ['verify now', 2],
      ['validate now', 2.5], ['confirm now', 2], ['login now', 2], ['log in now', 2], ['sign in now', 2], ['update your account', 2],
      ['account update', 1.5], ['account information', 1], ['account details', 1], ['web admin', 2.5], ['webmaster', 1.5], ['email administrator', 3],
      ['system administrator', 2.5], ['help desk', 2], ['helpdesk', 2], ['it support', 1.5], ['it department', 1.5], ['it service', 1.5],
      ['outlook web app', 2.5], ['owa', 1.5], ['cpanel', 2], ['roundcube', 2], ['zimbra', 2], ['mail server', 1.5], ['email server', 1.5],
      ['maintenance', 1], ['security update', 1.5], ['security notice', 1.5], ['unusual login', 2], ['new sign-in', 1.5], ['login attempt', 2],
      ['to avoid', 1], ['to continue using', 2], ['continue to use', 1.5], ['keep your account', 2.5], ['retain your account', 3], ['avoid losing', 2.5],
      ['re-validate', 3], ['revalidate', 3], ['validate your email', 3], ['validate your e-mail', 3], ['validate e-mail', 3], ['validate email', 2.5], ['email password', 2.5],
      ['e-mail password', 2.5], ['account termination', 3], ['termination', 1.5], ['closure of your', 2.5], ['account closure', 2.5], ['pending message', 2.5],
      ['account has been limited', 3], ['limited account', 3], ['account limitation', 3], ['restore your account', 3], ['resolve the issue', 1.5],
      ['verify your information', 3], ['confirm your information', 3], ['update your information', 2.5], ['email account holder', 3], ['kindly', 0.5],
      ['click here', 0.8], ['click the link', 1], ['click below', 1], ['follow the link', 1],
      ['password is expiring', 3], ['password expires today', 3], ['keep the same password', 3], ['retain credentials', 3], ['retain your credentials', 3],
      ['refresh email server', 3], ['dns server', 1.5], ['failing to deliver', 2.5], ['emails are failing', 3], ['imap', 1], ['pop3', 1],
      ['sent you a message', 1.5], ['view message', 1.5], ['new voicemail', 2], ['your mailbox', 1.5],
      // Spanish · Portuguese · German · French · Italian core lure vocabulary.
      ['tu cuenta', 1.5], ['su cuenta', 1.5], ['contraseña', 2], ['verifique', 1.5], ['verificar su', 2], ['desactivada', 2.5], ['desactivación', 2.5], ['suspendida', 2.5],
      ['iniciar sesión', 1.5], ['correo electrónico', 1], ['actualice', 1.5], ['actualizar sus datos', 3], ['sua conta', 1.5], ['senha', 2], ['bloqueada', 2.5],
      ['suspensa', 2.5], ['atualize', 1.5], ['atualizar seus dados', 3], ['ihr konto', 1.5], ['passwort', 2], ['kennwort', 2], ['gesperrt', 2.5], ['überprüfen', 1.5],
      ['bestätigen sie', 2], ['konto informationen', 2.5], ['votre compte', 1.5], ['mot de passe', 2], ['suspendu', 2.5], ['vérifier', 1.5], ['confirmer vos', 2.5],
      ['il tuo account', 1.5], ['sospeso', 2.5], ['verifica il', 2], ['novo acesso', 2.5], ['detectamos', 1.5], ['nuevo acceso', 2.5], ['nouvelle connexion', 2.5],
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
      ['membership is on hold', 3], ['account on hold', 3], ['account is on hold', 3], ['on hold', 1], ['payment information', 2], ['payment details', 2],
      ['billing problem', 3], ['billing issue', 2.5], ['trouble with your', 2], ['unable to process your payment', 3], ['payment could not be processed', 3],
      ['update payment', 2.5], ['payment method', 1.5], ['declined', 1], ['refund', 1], ['transaction', 0.5], ['wire', 1], ['bank account', 1.5],
      ['proof of payment', 2.5], ['payment confirmation', 1.5], ['transfer confirmation', 2], ['swift copy', 3], ['payment slip', 2.5], ['bank transfer', 1.5],
      ['problema en el pago', 3], ['membresía', 2], ['pagamento', 1.5], ['fatura', 1.5], ['zahlung', 1.5], ['rechnung', 1.5], ['paiement', 1.5], ['facture', 1.5], ['fattura', 1.5],
      ['transacao pendente', 3], ['compra em analise', 3], ['transaccion pendiente', 3], ['compra pendiente', 2.5], ['protocolo', 1],
    ],
  },
  {
    id: 'giftcard', label: 'Gift-card scam', action: 'buy gift cards',
    phrases: [['gift card', 2.5], ['gift cards', 2.5], ['itunes card', 3], ['google play card', 3], ['steam card', 3], ['scratch the back', 3], ['send me the codes', 3], ['are you available', 1.5], ['quick favor', 2], ['i need a favor', 2]],
  },
  {
    id: 'crypto', label: 'Crypto theft', action: 'connect wallet or share seed',
    phrases: [
      ['seed phrase', 3.5], ['recovery phrase', 3.5], ['secret phrase', 3], ['private key', 2.5], ['connect your wallet', 3], ['wallet validation', 3], ['claim your tokens', 3],
      ['airdrop', 2], ['usdt', 1.5], ['bitcoin', 1], ['metamask', 1.5], ['synchronize your wallet', 3], ['staking', 2], ['stake your', 2.5], ['yields', 1], ['apy', 1.5],
      ['confirm your keys', 3.5], ['secure your wallet', 2.5], ['wallet', 1], ['xlm', 1.5], ['crypto', 1], ['trust wallet', 2], ['ledger', 1], ['withdrawal', 1],
      ['xrp', 1.5], ['claim your xrp', 3], ['distribution', 0.8], ['nft', 1.5], ['mint', 0.8], ['token', 1], ['giveaway', 1.5], ['double your', 3],
    ],
  },
  {
    id: 'mfa', label: 'MFA / device-code theft', action: 'enter or share a code',
    phrases: [['devicelogin', 3.5], ['device code', 3], ['enter the code', 2], ['enter this code', 2], ['approve the sign-in', 2.5], ['approve the request', 2], ['share the code', 3], ['one-time code', 1.5], ['verification code', 1], ['otp', 1], ['authenticator app', 1.5]],
  },
  {
    id: 'delivery', label: 'Delivery scam', action: 'pay a fee or reschedule',
    phrases: [
      ['delivery failed', 3], ['failed delivery', 3], ['unable to deliver', 3], ['could not be delivered', 2.5], ['customs fee', 3], ['redelivery', 2.5], ['reschedule delivery', 2.5],
      ['shipping fee', 2], ['package is on hold', 3], ['parcel is on hold', 3], ['held at', 1.5], ['tracking number', 1], ['your package', 1], ['your parcel', 1.5],
      ['address incomplete', 3], ['confirm your address', 2], ['package is ready', 2], ['ready for delivery', 1.5], ['confirm the payment', 2.5], ['delivery fee', 3],
      ['address is missing', 3], ['missing address', 3], ['update your address', 2.5], ['delivery attempt', 2.5], ['shipment confirmation', 1],
      ['pay cost', 2.5], ['informed delivery', 2], ['shipment', 1], ['consignment', 1.5], ['waybill', 2], ['awb', 1.5], ['paquete', 1.5], ['encomenda', 1.5], ['paket', 1.5], ['colis', 1.5],
    ],
  },
  {
    id: 'document', label: 'Fake shared document', action: 'open a shared file',
    phrases: [
      ['shared a document', 2.5], ['shared a file', 2.5], ['has shared', 1.5], ['view document', 2], ['review document', 2], ['review and sign', 2], ['please review and sign', 2.5],
      ['e-signature', 1.5], ['secure message', 2], ['encrypted message', 2], ['voicemail', 2], ['voice message', 2], ['fax', 1.5], ['sent you a file', 2.5], ['document is ready', 2],
      ['access the document', 2.5], ['open the document', 2], ['scan document', 1.5], ['new document', 2], ['document has arrived', 3], ['shared with you', 2], ['view shared', 2.5],
      ['access your file', 2.5], ['view file', 2], ['download file', 1.5], ['file transfer', 1.5], ['wetransfer', 1.5], ['onedrive', 1.5], ['sharepoint', 1.5], ['docusign', 1.5],
      ['view attachment', 2], ['view the attachment', 2], ['proposal', 1], ['rfq', 2], ['request for quotation', 2.5], ['purchase order', 1.5], ['remittance advice', 2.5],
      ['uploaded for you', 3], ['document i uploaded', 3], ['view the document', 2.5], ['important document', 2], ['tax document', 2], ['send you some docs', 3],
      ['able to attach', 2], ['docs', 0.5], ['documento', 1.5], ['dokument', 1.5],
      ['new order', 1.5], ['please confirm', 0.8], ['lead time', 1.5], ['quotation', 1.5], ['price list', 1.5], ['order sheet', 2], ['shared folder', 2], ['folder has been shared', 2.5],
    ],
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
    phrases: [
      ['you have won', 3], ["you've won", 3], ['you are a winner', 3], ['lottery', 3], ['prize', 1.5], ['claim your reward', 3], ['claim your prize', 3], ['cash prize', 3],
      ['lucky draw', 3], ['congratulations', 1], ['selected to receive', 2.5], ['free gift', 2], ['reward points', 1.5], ['points will expire', 2.5], ['exclusive reward', 2],
      ['cashback', 1], ['you have been selected', 2.5], ['gewinner', 2.5], ['gewinnen sie', 2.5], ['gutschein', 2], ['ausgewahlt', 2], ['produkt tester', 2.5],
      ['voce foi selecionado', 2.5], ['ganhe', 1.5], ['premio', 2], ['ganador', 2.5], ['felicidades', 1.5], ['gagnant', 2.5], ['vincitore', 2.5], ['make money', 2],
      ['winner', 2], ['free spins', 2.5], ['freispiele', 2.5], ['casino', 1.5], ['jackpot', 2], ['welcome bonus', 2], ['deposit bonus', 2.5], ['claim your bonus', 2.5],
      ['bonus', 0.8], ['giveaway', 2], ['mystery box', 2.5], ['hai vinto', 2.5], ['drawn from our database', 3], ['you have been drawn', 3], ['recompense', 1.5],
      ['cadeau', 1], ['gratuit', 1], ['gratis', 1], ['free iphone', 3], ['confirm receipt', 1.5], ['claim now', 2],
    ],
  },
  {
    id: 'extortion', label: 'Extortion / sextortion', action: 'pay a ransom',
    phrases: [['i have access to your', 3], ['recorded you', 3.5], ['your webcam', 3], ['hacked your', 3], ['bitcoin address', 3], ['btc address', 3], ['pay within', 2.5], ['48 hours to pay', 3.5], ['compromising', 2], ['your contacts will', 3], ['i know your password', 3.5]],
  },
  {
    id: 'callback', label: 'Call-back (TOAD) scam', action: 'call a phone number',
    phrases: [
      ['call us at', 2], ['call our', 1.5], ['helpline', 1.5], ['toll free', 1.5], ['toll-free', 1.5], ['if you did not authorize', 2.5], ["if you didn't authorize", 2.5],
      ['did not make this purchase', 3], ['cancel your subscription', 1.5], ['auto-renewal', 2], ['has been renewed', 2], ['order has been placed', 2], ['to cancel', 1],
      ['billing department', 2], ['refund department', 3], ['payment received', 1.5], ['payment confirmed', 1.5], ['has been processed', 1.5], ['order id', 1],
      ['will be charged', 2], ['has been charged', 2], ['renewal', 1], ['subscription renewed', 2.5], ['if you wish to cancel', 2.5], ['contact us immediately', 2],
      ['call immediately', 2.5], ['support team', 0.8], ['invoice', 0.8], ['receipt', 0.5],
      ["don't recognize", 2], ['do not recognize', 2], ['did not place this order', 3], ['not placed by you', 3], ['thank you for your order', 1],
      ['order confirmation', 1], ['renewing', 1.5], ['membership is renewing', 3], ['auto-renew', 2], ['automatically renewed', 2.5], ['call now', 2],
      ['quickly call', 3], ['dispute', 1.5], ['unauthorized charge', 2.5],
    ],
  },
  {
    id: 'bec', label: 'CEO / business email compromise', action: 'reply and act discreetly',
    phrases: [['are you at your desk', 3], ['are you available', 1.5], ['i need you to', 1.5], ['confidential', 1], ['keep this between us', 3], ['do not discuss', 2.5], ['urgent task', 2.5], ['i am in a meeting', 2.5], ["i'm in a meeting", 2.5], ['reply with your', 2], ['send me your', 1.5], ['your cell number', 2.5], ['whatsapp number', 2.5]],
  },
];

/** Display names that pose as an IT / mail-system role rather than a person or brand. */
export const ROLE_NAMES = /\b(e-?mail\s*(admin(istrator)?|support|security|team|service|centre|center|update|verification|notification)|web\s*-?mail|mail\s*(admin|delivery|system|server|service|team|center|centre)|mailbox|postmaster|mailer-daemon|help\s*-?desk|service\s*desk|it\s*(support|service|department|team|desk|admin|helpdesk)|system\s*admin(istrator)?|sys\s*admin|administrator|admin\s*(team|center|centre|desk)?|security\s*(team|center|centre|alert|department|notice)|account\s*(services?|team|security|verification)|technical\s*support|tech\s*support|web\s*admin|webmaster|server\s*admin|domain\s*admin|cpanel|quota|storage\s*alert|notification\s*(center|centre|service)?)\b/i;

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
