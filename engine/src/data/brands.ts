// Brand registry: the most-impersonated brands worldwide plus major Indian brands.
// `domains` are registrable domains the brand legitimately sends from or links to.
// `names` are lowercase phrases matched on word boundaries. `ambiguous` brands (common words)
// only count when they appear in the sender display name or next to a context word.

import { deobfuscate } from '../util/text';

export interface Brand {
  id: string;
  name: string;
  names: string[];
  domains: string[];
  ambiguous?: boolean;
  context?: string[];
}

export const BRANDS: Brand[] = [
  // ── Technology & productivity ────────────────────────────────────────────
  {
    id: 'microsoft', name: 'Microsoft', names: ['microsoft', 'office 365', 'office365', 'microsoft 365', 'm365', 'outlook account', 'outlook web', 'outlook mailbox', 'onedrive', 'sharepoint', 'microsoft teams', 'microsoft azure', 'azure ad', 'xbox', 'hotmail', 'windows defender', 'microsoft account'],
    domains: ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'office.net', 'outlook.com', 'live.com', 'hotmail.com', 'msn.com', 'azure.com', 'windows.com', 'windows.net', 'sharepoint.com', 'onedrive.com', 'xbox.com', 'skype.com', 'bing.com', 'microsoftstore.com', 'msftauth.net', 'msauth.net', 'aka.ms', 'microsoft365.com', 'cloud.microsoft', 'mail.microsoft', 'dynamics.com', 'visualstudio.com', 'azureedge.net', 'sfx.ms', 'microsoftsupport.com', 'onenote.com'],
  },
  { id: 'google', name: 'Google', names: ['google', 'gmail', 'google drive', 'google docs', 'google workspace', 'youtube', 'google play', 'google pay'], domains: ['google.com', 'google.co.in', 'youtube.com', 'gmail.com', 'googlemail.com', 'gstatic.com', 'googleusercontent.com', 'withgoogle.com', 'goo.gl', 'g.co', 'googleapis.com', 'android.com', 'blogger.com', 'google.dev'] },
  { id: 'apple', name: 'Apple', names: ['apple', 'icloud', 'apple id', 'appleid', 'itunes', 'app store', 'appstore', 'apple pay', 'apple support'], domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.com', 'apple.news', 'appleid.apple.com', 'mzstatic.com', 'apps.apple.com'], ambiguous: true, context: ['id', 'icloud', 'account', 'store', 'pay', 'support', 'iphone', 'ipad', 'macbook', 'subscription', 'itunes'] },
  { id: 'amazon', name: 'Amazon', names: ['amazon', 'amazon prime', 'prime video', 'prime membership', 'aws', 'amazon web services', 'kindle'], domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazonaws.com', 'aws.amazon.com', 'primevideo.com', 'amazonses.com', 'media-amazon.com', 'amazon.jobs', 'awsapps.com', 'kindle.com', 'a2z.com', 'amzn.to', 'amazonpay.in', 'aboutamazon.com'] },
  { id: 'meta', name: 'Meta / Facebook', names: ['facebook', 'meta', 'instagram', 'whatsapp', 'messenger', 'meta business', 'facebook ads'], domains: ['facebook.com', 'facebookmail.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'messenger.com', 'metamail.com', 'fbcdn.net', 'threads.net', 'mail.instagram.com'], ambiguous: true, context: ['facebook', 'instagram', 'business', 'ads', 'page', 'account', 'verified', 'copyright', 'violation'] },
  { id: 'linkedin', name: 'LinkedIn', names: ['linkedin'], domains: ['linkedin.com', 'licdn.com', 'lnkd.in', 'linkedinmail.com'] },
  { id: 'twitter', name: 'X / Twitter', names: ['twitter', 'x corp'], domains: ['twitter.com', 'x.com', 't.co', 'twimg.com'] },
  { id: 'dropbox', name: 'Dropbox', names: ['dropbox'], domains: ['dropbox.com', 'dropboxmail.com', 'db.tt', 'dropboxusercontent.com'] },
  { id: 'docusign', name: 'DocuSign', names: ['docusign', 'docu sign'], domains: ['docusign.com', 'docusign.net', 'docusign.eu'] },
  { id: 'adobe', name: 'Adobe', names: ['adobe', 'adobe sign', 'acrobat', 'adobe document cloud'], domains: ['adobe.com', 'adobesign.com', 'adobe.io', 'echosign.com', 'adobelogin.com', 'mail.adobe.com'] },
  { id: 'zoom', name: 'Zoom', names: ['zoom meeting', 'zoom video', 'zoom us', 'zoom.us'], domains: ['zoom.us', 'zoom.com', 'zoomgov.com'] },
  { id: 'slack', name: 'Slack', names: ['slack'], domains: ['slack.com', 'slack-edge.com', 'slackbot.com'], ambiguous: true, context: ['workspace', 'channel', 'message', 'invite'] },
  { id: 'github', name: 'GitHub', names: ['github'], domains: ['github.com', 'githubusercontent.com', 'github.io', 'githubapp.com'] },
  { id: 'wetransfer', name: 'WeTransfer', names: ['wetransfer', 'we transfer'], domains: ['wetransfer.com', 'we.tl'] },
  { id: 'okta', name: 'Okta', names: ['okta'], domains: ['okta.com', 'oktacdn.com', 'okta-emea.com'] },
  { id: 'salesforce', name: 'Salesforce', names: ['salesforce'], domains: ['salesforce.com', 'force.com', 'exacttarget.com'] },
  { id: 'zoho', name: 'Zoho', names: ['zoho'], domains: ['zoho.com', 'zoho.in', 'zohomail.com', 'zohocorp.com'] },
  { id: 'canva', name: 'Canva', names: ['canva'], domains: ['canva.com', 'canva.site'] },
  { id: 'norton', name: 'Norton', names: ['norton', 'norton 360', 'norton antivirus', 'nortonlifelock', 'gen digital'], domains: ['norton.com', 'nortonlifelock.com', 'gendigital.com', 'symantec.com'], ambiguous: true, context: ['antivirus', 'subscription', '360', 'lifelock', 'renewal', 'renewed', 'protection', 'invoice', 'order'] },
  { id: 'mcafee', name: 'McAfee', names: ['mcafee', 'mc afee'], domains: ['mcafee.com', 'mcafee.co.in'] },
  { id: 'geeksquad', name: 'Geek Squad', names: ['geek squad', 'geeksquad', 'best buy'], domains: ['bestbuy.com', 'geeksquad.com'] },
  { id: 'intuit', name: 'Intuit / QuickBooks', names: ['intuit', 'quickbooks', 'turbotax', 'mailchimp'], domains: ['intuit.com', 'quickbooks.com', 'turbotax.com', 'mailchimp.com', 'notification.intuit.com'] },
  { id: 'netflix', name: 'Netflix', names: ['netflix'], domains: ['netflix.com', 'netflix.net', 'nflxext.com', 'mailer.netflix.com'] },
  { id: 'spotify', name: 'Spotify', names: ['spotify'], domains: ['spotify.com', 'spotifymail.com', 'scdn.co'] },
  { id: 'disney', name: 'Disney+', names: ['disney+', 'disney plus', 'hotstar', 'jiohotstar'], domains: ['disneyplus.com', 'disney.com', 'hotstar.com', 'jiohotstar.com'] },
  { id: 'steam', name: 'Steam', names: ['steam', 'steam community', 'valve'], domains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'], ambiguous: true, context: ['account', 'community', 'trade', 'gift', 'wallet', 'guard'] },
  { id: 'roblox', name: 'Roblox', names: ['roblox'], domains: ['roblox.com'] },
  { id: 'samsung', name: 'Samsung', names: ['samsung'], domains: ['samsung.com'] },
  { id: 'yahoo', name: 'Yahoo', names: ['yahoo', 'yahoo mail'], domains: ['yahoo.com', 'yahoo.co.in', 'yahoo.net', 'yahooinc.com', 'yahoogroups.com', 'yimg.com', 'yahoodns.net'] },
  { id: 'openai', name: 'OpenAI / ChatGPT', names: ['openai', 'chatgpt'], domains: ['openai.com', 'chatgpt.com', 'tm.openai.com'] },

  // ── Finance & payments ───────────────────────────────────────────────────
  { id: 'paypal', name: 'PayPal', names: ['paypal', 'pay pal'], domains: ['paypal.com', 'paypal.me', 'paypal-communication.com', 'paypalobjects.com', 'paypal.co.uk', 'paypal.in', 'xoom.com', 'venmo.com'] },
  { id: 'stripe', name: 'Stripe', names: ['stripe'], domains: ['stripe.com', 'stripe.network'], ambiguous: true, context: ['payment', 'payout', 'invoice', 'account', 'dashboard'] },
  { id: 'visa', name: 'Visa', names: ['visa card', 'visa secure', 'verified by visa'], domains: ['visa.com', 'visa.co.in'] },
  { id: 'mastercard', name: 'Mastercard', names: ['mastercard', 'master card'], domains: ['mastercard.com', 'mastercard.co.in'] },
  { id: 'amex', name: 'American Express', names: ['american express', 'amex'], domains: ['americanexpress.com', 'aexp.com', 'amex.com', 'welcome.aexp.com'] },
  { id: 'chase', name: 'Chase', names: ['chase bank', 'jpmorgan chase', 'jp morgan', 'chase online', 'chase alert'], domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com', 'alertsp.chase.com'] },
  { id: 'bofa', name: 'Bank of America', names: ['bank of america', 'bofa'], domains: ['bankofamerica.com', 'bofa.com', 'ealerts.bankofamerica.com'] },
  { id: 'wellsfargo', name: 'Wells Fargo', names: ['wells fargo', 'wellsfargo'], domains: ['wellsfargo.com', 'wf.com', 'wellsfargoemail.com'] },
  { id: 'citi', name: 'Citibank', names: ['citibank', 'citi bank', 'citigroup'], domains: ['citi.com', 'citibank.com', 'citigroup.com', 'citibank.co.in'] },
  { id: 'capitalone', name: 'Capital One', names: ['capital one', 'capitalone'], domains: ['capitalone.com', 'capitalone.co.uk'] },
  { id: 'hsbc', name: 'HSBC', names: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.co.in', 'us.hsbc.com'] },
  { id: 'barclays', name: 'Barclays', names: ['barclays'], domains: ['barclays.com', 'barclays.co.uk', 'barclaycard.co.uk'] },
  { id: 'santander', name: 'Santander', names: ['santander'], domains: ['santander.com', 'santander.co.uk', 'santanderbank.com'] },
  { id: 'coinbase', name: 'Coinbase', names: ['coinbase'], domains: ['coinbase.com', 'coinbase.io'] },
  { id: 'binance', name: 'Binance', names: ['binance'], domains: ['binance.com', 'binance.us'] },
  { id: 'metamask', name: 'MetaMask', names: ['metamask', 'meta mask'], domains: ['metamask.io', 'consensys.io', 'consensys.net'] },
  { id: 'ledger', name: 'Ledger', names: ['ledger live', 'ledger wallet', 'ledger nano', 'ledger'], domains: ['ledger.com'], ambiguous: true, context: ['wallet', 'crypto', 'nano', 'live', 'seed', 'recovery', 'firmware', 'bitcoin'] },
  { id: 'trustwallet', name: 'Trust Wallet', names: ['trust wallet', 'trustwallet'], domains: ['trustwallet.com'] },
  { id: 'wise', name: 'Wise', names: ['transferwise', 'wise transfer', 'wise'], domains: ['wise.com', 'transferwise.com'], ambiguous: true, context: ['transfer', 'account', 'payment', 'money', 'card', 'balance'] },
  { id: 'schwab', name: 'Charles Schwab', names: ['charles schwab', 'schwab'], domains: ['schwab.com'] },
  { id: 'fidelity', name: 'Fidelity', names: ['fidelity investments'], domains: ['fidelity.com'] },
  { id: 'robinhood', name: 'Robinhood', names: ['robinhood'], domains: ['robinhood.com'] },
  { id: 'kraken', name: 'Kraken', names: ['kraken exchange'], domains: ['kraken.com'] },
  { id: 'stellar', name: 'Stellar', names: ['stellar.org', 'stellar lumens', 'xlm'], domains: ['stellar.org'] },
  { id: 'westernunion', name: 'Western Union', names: ['western union'], domains: ['westernunion.com', 'wu.com'] },
  { id: 'moneygram', name: 'MoneyGram', names: ['moneygram'], domains: ['moneygram.com'] },
  // India: banking, payments, government
  { id: 'sbi', name: 'State Bank of India', names: ['state bank of india', 'sbi', 'yono', 'onlinesbi'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi', 'sbicard.com', 'yonobusiness.sbi', 'onlinesbi.com', 'sbi.bank.in', 'bank.in'] },
  { id: 'hdfc', name: 'HDFC Bank', names: ['hdfc', 'hdfc bank', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net', 'hdfcbank.bank.in', 'hdfcsec.com', 'hdfclife.com', 'hdfcergo.com'] },
  { id: 'icici', name: 'ICICI Bank', names: ['icici', 'icici bank', 'imobile'], domains: ['icicibank.com', 'icici.com', 'icicidirect.com', 'icicilombard.com', 'iciciprulife.com', 'icicibank.bank.in'] },
  { id: 'axis', name: 'Axis Bank', names: ['axis bank', 'axisbank'], domains: ['axisbank.com', 'axisbank.co.in', 'axis.bank.in'] },
  { id: 'kotak', name: 'Kotak Mahindra Bank', names: ['kotak', 'kotak mahindra', 'kotak bank'], domains: ['kotak.com', 'kotaksecurities.com', 'kotak.bank.in'] },
  { id: 'pnb', name: 'Punjab National Bank', names: ['punjab national bank', 'pnb'], domains: ['pnbindia.in', 'pnb.co.in', 'pnb.bank.in'] },
  { id: 'bob', name: 'Bank of Baroda', names: ['bank of baroda'], domains: ['bankofbaroda.in', 'bankofbaroda.com', 'bankofbaroda.bank.in'] },
  { id: 'paytm', name: 'Paytm', names: ['paytm'], domains: ['paytm.com', 'paytm.in', 'paytmbank.com', 'paytmmoney.com'] },
  { id: 'phonepe', name: 'PhonePe', names: ['phonepe', 'phone pe'], domains: ['phonepe.com'] },
  { id: 'gpay', name: 'Google Pay (India)', names: ['gpay', 'google pay'], domains: ['google.com', 'pay.google.com', 'gpay.app.goo.gl'] },
  { id: 'npci', name: 'NPCI / UPI', names: ['npci', 'bhim upi', 'upi'], domains: ['npci.org.in', 'bhimupi.org.in'], ambiguous: true, context: ['npci', 'bhim', 'upi pin', 'upi id', 'collect request', 'kyc'] },
  { id: 'rbi', name: 'Reserve Bank of India', names: ['reserve bank of india', 'rbi'], domains: ['rbi.org.in'] },
  { id: 'incometax', name: 'Income Tax Department (India)', names: ['income tax department', 'income tax refund', 'itr refund', 'efiling', 'e-filing', 'cbdt'], domains: ['incometax.gov.in', 'incometaxindia.gov.in', 'gov.in', 'nic.in'] },
  { id: 'uidai', name: 'UIDAI / Aadhaar', names: ['aadhaar', 'aadhar', 'uidai'], domains: ['uidai.gov.in', 'gov.in'] },
  { id: 'gst', name: 'GST Network', names: ['gstn', 'gst portal', 'gst notice', 'goods and services tax'], domains: ['gst.gov.in', 'gov.in'] },
  { id: 'epfo', name: 'EPFO', names: ['epfo', 'provident fund', 'uan'], domains: ['epfindia.gov.in', 'gov.in'], ambiguous: true, context: ['epfo', 'pf', 'provident', 'withdrawal', 'claim', 'kyc'] },
  { id: 'lic', name: 'LIC', names: ['life insurance corporation', 'lic of india', 'lic policy'], domains: ['licindia.in', 'licindia.com'] },
  { id: 'irctc', name: 'IRCTC', names: ['irctc', 'indian railways'], domains: ['irctc.co.in', 'irctc.com', 'indianrail.gov.in'] },
  { id: 'indiapost', name: 'India Post', names: ['india post', 'indiapost', 'speed post'], domains: ['indiapost.gov.in', 'gov.in'] },
  { id: 'digilocker', name: 'DigiLocker', names: ['digilocker'], domains: ['digilocker.gov.in', 'gov.in'] },
  // Global government / tax
  { id: 'irs', name: 'IRS', names: ['internal revenue service', 'irs'], domains: ['irs.gov', 'treasury.gov'] },
  { id: 'hmrc', name: 'HMRC', names: ['hmrc', 'hm revenue', 'hm revenue & customs'], domains: ['hmrc.gov.uk', 'gov.uk'] },
  { id: 'ssa', name: 'Social Security Administration', names: ['social security administration', 'ssa'], domains: ['ssa.gov'] },
  { id: 'cra', name: 'Canada Revenue Agency', names: ['canada revenue agency', 'cra'], domains: ['canada.ca', 'cra-arc.gc.ca', 'gc.ca'], ambiguous: true, context: ['canada', 'revenue', 'benefit', 'refund', 'tax'] },
  { id: 'ato', name: 'Australian Taxation Office', names: ['australian taxation office', 'mygov'], domains: ['ato.gov.au', 'my.gov.au', 'gov.au'] },

  // ── Shipping & retail ────────────────────────────────────────────────────
  { id: 'dhl', name: 'DHL', names: ['dhl', 'dhl express'], domains: ['dhl.com', 'dhl.de', 'dhl.co.in', 'dhl.co.uk', 'dhlecommerce.com', 'dpdhl.com', 'dhl-news.com'] },
  { id: 'fedex', name: 'FedEx', names: ['fedex', 'fed ex'], domains: ['fedex.com', 'fedex.co.in', 'fedexmail.com'] },
  { id: 'ups', name: 'UPS', names: ['united parcel service', 'ups delivery', 'ups package', 'ups my choice'], domains: ['ups.com', 'upsmail.com', 'ups-mi.net'] },
  { id: 'usps', name: 'USPS', names: ['usps', 'united states postal service', 'us postal service'], domains: ['usps.com', 'usps.gov', 'informeddelivery.usps.com'] },
  { id: 'royalmail', name: 'Royal Mail', names: ['royal mail'], domains: ['royalmail.com', 'royalmail.co.uk'] },
  { id: 'canadapost', name: 'Canada Post', names: ['canada post', 'postes canada'], domains: ['canadapost.ca', 'canadapost-postescanada.ca'] },
  { id: 'auspost', name: 'Australia Post', names: ['australia post', 'auspost'], domains: ['auspost.com.au'] },
  { id: 'bluedart', name: 'Blue Dart', names: ['blue dart', 'bluedart'], domains: ['bluedart.com'] },
  { id: 'delhivery', name: 'Delhivery', names: ['delhivery'], domains: ['delhivery.com'] },
  { id: 'aramex', name: 'Aramex', names: ['aramex'], domains: ['aramex.com'] },
  { id: 'maersk', name: 'Maersk', names: ['maersk'], domains: ['maersk.com'] },
  { id: 'walmart', name: 'Walmart', names: ['walmart'], domains: ['walmart.com', 'walmart.ca', 'email.walmart.com'] },
  { id: 'ebay', name: 'eBay', names: ['ebay'], domains: ['ebay.com', 'ebay.co.uk', 'ebay.in', 'ebay.de', 'ebayinc.com'] },
  { id: 'flipkart', name: 'Flipkart', names: ['flipkart'], domains: ['flipkart.com', 'flipkartmail.com', 'fkrt.it'] },
  { id: 'myntra', name: 'Myntra', names: ['myntra'], domains: ['myntra.com'] },
  { id: 'meesho', name: 'Meesho', names: ['meesho'], domains: ['meesho.com'] },
  { id: 'swiggy', name: 'Swiggy', names: ['swiggy'], domains: ['swiggy.com', 'swiggy.in'] },
  { id: 'zomato', name: 'Zomato', names: ['zomato'], domains: ['zomato.com'] },
  { id: 'airtel', name: 'Airtel', names: ['airtel', 'bharti airtel'], domains: ['airtel.in', 'airtel.com'] },
  { id: 'jio', name: 'Jio', names: ['reliance jio', 'jio', 'myjio'], domains: ['jio.com', 'ril.com', 'jio.in'], ambiguous: true, context: ['recharge', 'sim', 'plan', 'kyc', 'fiber', 'airfiber', 'reliance'] },
  { id: 'vi', name: 'Vodafone Idea', names: ['vodafone idea', 'vodafone'], domains: ['myvi.in', 'vodafone.com', 'vodafone.co.uk', 'vodafone.in'] },
  { id: 'att', name: 'AT&T', names: ['at&t', 'att wireless'], domains: ['att.com', 'att.net', 'att-mail.com'] },
  { id: 'verizon', name: 'Verizon', names: ['verizon'], domains: ['verizon.com', 'verizonwireless.com', 'vzw.com'] },
  { id: 'xfinity', name: 'Comcast Xfinity', names: ['xfinity', 'comcast'], domains: ['xfinity.com', 'comcast.com', 'comcast.net'] },
  { id: 'booking', name: 'Booking.com', names: ['booking.com'], domains: ['booking.com', 'bstatic.com'] },
  { id: 'airbnb', name: 'Airbnb', names: ['airbnb'], domains: ['airbnb.com', 'airbnb.co.in', 'airbnbmail.com'] },
  { id: 'uber', name: 'Uber', names: ['uber'], domains: ['uber.com', 'ubereats.com'] },
  { id: 'costco', name: 'Costco', names: ['costco'], domains: ['costco.com'] },
  { id: 'shopify', name: 'Shopify', names: ['shopify'], domains: ['shopify.com', 'myshopify.com', 'shopifyemail.com'] },

  // ── More banks (frequently impersonated worldwide) ───────────────────────
  { id: 'usaa', name: 'USAA', names: ['usaa'], domains: ['usaa.com'] },
  { id: 'fifththird', name: 'Fifth Third Bank', names: ['fifth third', '53 bank', 'fifththird'], domains: ['53.com', 'fifththird.com'] },
  { id: 'pnc', name: 'PNC Bank', names: ['pnc bank', 'pnc online'], domains: ['pnc.com'] },
  { id: 'usbank', name: 'U.S. Bank', names: ['u.s. bank', 'us bank', 'usbank'], domains: ['usbank.com'] },
  { id: 'tdbank', name: 'TD Bank', names: ['td bank', 'td canada trust', 'td ameritrade'], domains: ['td.com', 'tdbank.com', 'tdameritrade.com'] },
  { id: 'regionsbank', name: 'Regions Bank', names: ['regions bank'], domains: ['regions.com'] },
  { id: 'truist', name: 'Truist', names: ['truist', 'suntrust', 'bb&t'], domains: ['truist.com', 'suntrust.com', 'bbt.com'] },
  { id: 'navyfederal', name: 'Navy Federal Credit Union', names: ['navy federal', 'navyfederal', 'nfcu'], domains: ['navyfederal.org'] },
  { id: 'citizensbank', name: 'Citizens Bank', names: ['citizens bank'], domains: ['citizensbank.com'] },
  { id: 'keybank', name: 'KeyBank', names: ['keybank', 'key bank'], domains: ['key.com'] },
  { id: 'huntington', name: 'Huntington Bank', names: ['huntington bank'], domains: ['huntington.com'] },
  { id: 'allybank', name: 'Ally Bank', names: ['ally bank', 'ally financial'], domains: ['ally.com'] },
  { id: 'discover', name: 'Discover', names: ['discover card', 'discover bank'], domains: ['discover.com'] },
  { id: 'natwest', name: 'NatWest', names: ['natwest', 'royal bank of scotland', 'rbs'], domains: ['natwest.com', 'rbs.co.uk'] },
  { id: 'lloyds', name: 'Lloyds Bank', names: ['lloyds bank', 'lloyds', 'halifax'], domains: ['lloydsbank.com', 'lloydsbank.co.uk', 'halifax.co.uk', 'lloydsbankinggroup.com'] },
  { id: 'rbc', name: 'RBC Royal Bank', names: ['royal bank of canada', 'rbc royal bank', 'rbc'], domains: ['rbc.com', 'rbcroyalbank.com'] },
  { id: 'scotiabank', name: 'Scotiabank', names: ['scotiabank'], domains: ['scotiabank.com'] },
  { id: 'bmo', name: 'BMO', names: ['bmo', 'bank of montreal'], domains: ['bmo.com'] },
  { id: 'cibc', name: 'CIBC', names: ['cibc'], domains: ['cibc.com'] },
  { id: 'desjardins', name: 'Desjardins', names: ['desjardins'], domains: ['desjardins.com'] },
  { id: 'interac', name: 'Interac', names: ['interac', 'e-transfer'], domains: ['interac.ca'] },
  { id: 'commbank', name: 'Commonwealth Bank', names: ['commonwealth bank', 'commbank', 'netbank'], domains: ['commbank.com.au'] },
  { id: 'anz', name: 'ANZ', names: ['anz bank', 'anz'], domains: ['anz.com', 'anz.com.au'] },
  { id: 'nab', name: 'NAB', names: ['national australia bank'], domains: ['nab.com.au'] },
  { id: 'westpac', name: 'Westpac', names: ['westpac'], domains: ['westpac.com.au'] },
  { id: 'ing', name: 'ING', names: ['ing bank', 'ing direct'], domains: ['ing.com', 'ing.nl', 'ing.de', 'ing.com.au'] },
  { id: 'abnamro', name: 'ABN AMRO', names: ['abn amro', 'abnamro'], domains: ['abnamro.nl', 'abnamro.com'] },
  { id: 'rabobank', name: 'Rabobank', names: ['rabobank'], domains: ['rabobank.nl', 'rabobank.com'] },
  { id: 'bnp', name: 'BNP Paribas', names: ['bnp paribas', 'bnp'], domains: ['bnpparibas.com', 'bnpparibas.fr', 'mabanque.bnpparibas'] },
  { id: 'socgen', name: 'Société Générale', names: ['societe generale', 'société générale'], domains: ['societegenerale.fr', 'societegenerale.com'] },
  { id: 'creditagricole', name: 'Crédit Agricole', names: ['credit agricole', 'crédit agricole'], domains: ['credit-agricole.fr', 'credit-agricole.com'] },
  { id: 'labanquepostale', name: 'La Banque Postale', names: ['banque postale'], domains: ['labanquepostale.fr'] },
  { id: 'deutschebank', name: 'Deutsche Bank', names: ['deutsche bank'], domains: ['db.com', 'deutsche-bank.de'] },
  { id: 'sparkasse', name: 'Sparkasse', names: ['sparkasse'], domains: ['sparkasse.de'] },
  { id: 'commerzbank', name: 'Commerzbank', names: ['commerzbank'], domains: ['commerzbank.de', 'commerzbank.com'] },
  { id: 'postbank', name: 'Postbank', names: ['postbank'], domains: ['postbank.de'] },
  { id: 'itau', name: 'Itaú', names: ['itau', 'itaú'], domains: ['itau.com.br'] },
  { id: 'bradesco', name: 'Bradesco', names: ['bradesco'], domains: ['bradesco.com.br'] },
  { id: 'bancodobrasil', name: 'Banco do Brasil', names: ['banco do brasil'], domains: ['bb.com.br'] },
  { id: 'caixa', name: 'Caixa', names: ['caixa economica', 'caixa econômica'], domains: ['caixa.gov.br'] },
  { id: 'nubank', name: 'Nubank', names: ['nubank', 'banco nu', 'nu bank'], domains: ['nubank.com.br', 'nu.com.mx'] },
  { id: 'mercadopago', name: 'Mercado Pago', names: ['mercado pago', 'mercadopago', 'mercado livre', 'mercado libre'], domains: ['mercadopago.com', 'mercadopago.com.br', 'mercadolivre.com.br', 'mercadolibre.com'] },
  { id: 'ripple', name: 'Ripple', names: ['ripple labs', 'ripple team'], domains: ['ripple.com'] },
  { id: 'opensea', name: 'OpenSea', names: ['opensea'], domains: ['opensea.io'] },
  { id: 'bbva', name: 'BBVA', names: ['bbva'], domains: ['bbva.com', 'bbva.es', 'bbva.mx'] },
  { id: 'caixabank', name: 'CaixaBank', names: ['caixabank', 'la caixa'], domains: ['caixabank.es', 'caixabank.com'] },
  { id: 'standardchartered', name: 'Standard Chartered', names: ['standard chartered'], domains: ['sc.com'] },
  { id: 'dbs', name: 'DBS Bank', names: ['dbs bank', 'posb'], domains: ['dbs.com', 'dbs.com.sg'] },
  { id: 'maybank', name: 'Maybank', names: ['maybank'], domains: ['maybank.com', 'maybank2u.com.my'] },
  { id: 'emiratesnbd', name: 'Emirates NBD', names: ['emirates nbd'], domains: ['emiratesnbd.com'] },
  { id: 'alrajhi', name: 'Al Rajhi Bank', names: ['al rajhi', 'alrajhi'], domains: ['alrajhibank.com.sa'] },
  { id: 'samba', name: 'Samba Financial Group', names: ['samba bank', 'samba financial', 'samba'], domains: ['samba.com'], ambiguous: true, context: ['bank', 'account', 'card', 'banking', 'customer'] },
  { id: 'unionbankindia', name: 'Union Bank of India', names: ['union bank of india'], domains: ['unionbankofindia.co.in', 'unionbankofindia.bank.in'] },
  { id: 'canarabank', name: 'Canara Bank', names: ['canara bank'], domains: ['canarabank.com', 'canarabank.in'] },
  { id: 'indusind', name: 'IndusInd Bank', names: ['indusind'], domains: ['indusind.com'] },
  { id: 'yesbank', name: 'YES Bank', names: ['yes bank'], domains: ['yesbank.in'] },
  { id: 'idfcfirst', name: 'IDFC FIRST Bank', names: ['idfc first', 'idfc bank'], domains: ['idfcfirstbank.com'] },
  { id: 'bankofindia', name: 'Bank of India', names: ['bank of india'], domains: ['bankofindia.co.in'] },
  // ── Couriers & postal services ───────────────────────────────────────────
  { id: 'tnt', name: 'TNT', names: ['tnt express', 'tnt'], domains: ['tnt.com'], ambiguous: true, context: ['shipment', 'parcel', 'delivery', 'tracking', 'express', 'consignment'] },
  { id: 'sfexpress', name: 'SF Express', names: ['sf express', 'sfexpress'], domains: ['sf-express.com', 'sf-international.com'] },
  { id: 'ems', name: 'EMS', names: ['ems tracking', 'ems parcel', 'express mail service'], domains: ['ems.post'] },
  { id: 'dpd', name: 'DPD', names: ['dpd'], domains: ['dpd.com', 'dpd.co.uk', 'dpd.de'], ambiguous: true, context: ['parcel', 'delivery', 'shipment', 'tracking', 'driver'] },
  { id: 'gls', name: 'GLS', names: ['gls parcel', 'gls'], domains: ['gls-group.eu', 'gls-group.com'], ambiguous: true, context: ['parcel', 'delivery', 'shipment', 'tracking'] },
  { id: 'hermes', name: 'Evri / Hermes', names: ['evri', 'hermes parcel', 'myhermes'], domains: ['evri.com', 'myhermes.co.uk', 'hermesworld.com'] },
  { id: 'postnl', name: 'PostNL', names: ['postnl'], domains: ['postnl.nl'] },
  { id: 'laposte', name: 'La Poste', names: ['la poste', 'colissimo', 'chronopost'], domains: ['laposte.fr', 'colissimo.fr', 'chronopost.fr'] },
  { id: 'correos', name: 'Correos', names: ['correos'], domains: ['correos.es'] },
  { id: 'posteitaliane', name: 'Poste Italiane', names: ['poste italiane'], domains: ['poste.it'] },
  { id: 'deutschepost', name: 'Deutsche Post', names: ['deutsche post'], domains: ['deutschepost.de', 'dhl.de'] },
  { id: 'swisspost', name: 'Swiss Post', names: ['swiss post', 'die post'], domains: ['post.ch'] },
  { id: 'japanpost', name: 'Japan Post', names: ['japan post'], domains: ['post.japanpost.jp', 'japanpost.jp'] },
  { id: 'emiratespost', name: 'Emirates Post', names: ['emirates post'], domains: ['emiratespost.ae'] },
  // ── Mail, hosting & identity platforms (IT-admin lures) ──────────────────
  { id: 'cpanel', name: 'cPanel', names: ['cpanel', 'webmail cpanel'], domains: ['cpanel.net', 'cpanel.com'] },
  { id: 'roundcube', name: 'Roundcube', names: ['roundcube'], domains: ['roundcube.net'] },
  { id: 'zimbra', name: 'Zimbra', names: ['zimbra'], domains: ['zimbra.com'] },
  { id: 'godaddy', name: 'GoDaddy', names: ['godaddy', 'go daddy'], domains: ['godaddy.com', 'secureserver.net'] },
  { id: 'namecheap', name: 'Namecheap', names: ['namecheap'], domains: ['namecheap.com'] },
  { id: 'aol', name: 'AOL', names: ['aol mail', 'aol'], domains: ['aol.com', 'aol.net'] },
  { id: 'proton', name: 'Proton Mail', names: ['protonmail', 'proton mail'], domains: ['proton.me', 'protonmail.com', 'proton.ch'] },

  // ── Employers & recruitment (common job-scam lures) ──────────────────────
  { id: 'ltimindtree', name: 'LTIMindtree', names: ['ltimindtree', 'lti mindtree', 'mind tree', 'mindtree', 'larsen & toubro infotech'], domains: ['ltimindtree.com', 'mindtree.com', 'lntinfotech.com'] },
  { id: 'tcs', name: 'Tata Consultancy Services', names: ['tata consultancy services', 'tcs nqt', 'tcs ion', 'tcs'], domains: ['tcs.com', 'tcsion.com', 'tata.com'], ambiguous: true, context: ['tcs', 'tata', 'nqt', 'ion', 'hiring', 'offer', 'interview'] },
  { id: 'infosys', name: 'Infosys', names: ['infosys'], domains: ['infosys.com', 'infosysbpm.com', 'infy.com'] },
  { id: 'wipro', name: 'Wipro', names: ['wipro'], domains: ['wipro.com'] },
  { id: 'hcl', name: 'HCLTech', names: ['hcl technologies', 'hcltech', 'hcl tech'], domains: ['hcltech.com', 'hcl.com'] },
  { id: 'accenture', name: 'Accenture', names: ['accenture'], domains: ['accenture.com'] },
  { id: 'deloitte', name: 'Deloitte', names: ['deloitte'], domains: ['deloitte.com'] },
  { id: 'cognizant', name: 'Cognizant', names: ['cognizant'], domains: ['cognizant.com'] },
  { id: 'capgemini', name: 'Capgemini', names: ['capgemini'], domains: ['capgemini.com'] },
  { id: 'ibm', name: 'IBM', names: ['ibm'], domains: ['ibm.com'] },
  { id: 'boeing', name: 'Boeing', names: ['boeing'], domains: ['boeing.com', 'myworkday.com', 'workday.com'] },
  { id: 'naukri', name: 'Naukri', names: ['naukri', 'naukri.com'], domains: ['naukri.com', 'naukrigulf.com', 'infoedge.com'] },
  { id: 'indeed', name: 'Indeed', names: ['indeed'], domains: ['indeed.com', 'indeedemail.com', 'indeed.co.in'], ambiguous: true, context: ['job', 'jobs', 'apply', 'application', 'resume', 'employer', 'hiring'] },
];

const BY_ID = new Map(BRANDS.map((b) => [b.id, b]));

export function brandById(id: string): Brand | undefined {
  return BY_ID.get(id);
}

/** Registrable domains belonging to any brand (for lookalike checks). */
export const BRAND_DOMAINS: { domain: string; label: string; brand: Brand }[] = BRANDS.flatMap((b) =>
  b.domains
    .filter((d) => d.includes('.') && !['gov.in', 'gov.uk', 'gov.au', 'gc.ca', 'nic.in', 'bank.in'].includes(d))
    .map((d) => ({ domain: d, label: d.split('.')[0] as string, brand: b })),
);

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const SERVICE_WORDS = /\b(support|team|service|services|security|alert|alerts|account|accounts|billing|customer|help|helpdesk|notification|notifications|update|info|no-?reply|noreply|care|center|centre|id|store|pay|wallet|online|official|protection|renewal|subscription)\b/;

function wordRe(alternatives: string[]): RegExp {
  return new RegExp(`(?:^|[^\\p{L}\\p{N}])(?:${alternatives.map(escapeRe).join('|')})(?=$|[^\\p{L}\\p{N}])`, 'iu');
}

const NAME_PATTERNS: { brand: Brand; re: RegExp; ctx: RegExp | null }[] = BRANDS.map((b) => ({
  brand: b,
  re: wordRe(b.names),
  ctx: b.context?.length ? wordRe(b.context) : null,
}));

/**
 * Brands mentioned in `text`. `strict` (display names) accepts ambiguous brands directly;
 * otherwise ambiguous brands need one of their context words nearby.
 */
export function findBrands(text: string, strict: boolean): Brand[] {
  if (!text) return [];
  const lower = text.toLowerCase();
  const out: Brand[] = [];
  for (const { brand, re, ctx } of NAME_PATTERNS) {
    if (!re.test(lower)) continue;
    if (brand.ambiguous) {
      const hasContext = !!ctx && ctx.test(lower);
      // In a display name an ambiguous brand ("Apple", "Norton") only counts when the name reads
      // like a service account ("Apple Support", "Norton") rather than a person ("Edward Norton").
      const serviceLike = strict && (lower.split(/\s+/).length <= 1 || SERVICE_WORDS.test(lower));
      if (!hasContext && !serviceLike) continue;
    }
    out.push(brand);
  }
  return out;
}

/** Display names are often obfuscated: "American .Express", "Geek<>Squad®", "AppStore", "NeIflíx". */
export function normalizeDisplayName(name: string): string {
  return deobfuscate(name)
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^\p{L}\p{N}&+]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

// Visual skeleton for brand-name comparison (I/l/1, 0/o, rn/m …). Kept local to avoid a cycle.
function nameSkeleton(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[1|!i]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a');
}

function editDistance(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0] as number;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j] as number;
      dp[j] = Math.min((dp[j] as number) + 1, (dp[j - 1] as number) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length] as number;
}

const FUZZY_NAMES: { brand: Brand; skel: string }[] = BRANDS.flatMap((b) =>
  b.ambiguous ? [] : b.names.map((n) => ({ brand: b, skel: nameSkeleton(n) })).filter((x) => x.skel.length >= 6),
);

/**
 * Brand claims in a sender display name, tolerant to punctuation, spacing, accents and homoglyph
 * misspellings (edit distance ≤ 1 on the visual skeleton, same first letter).
 */
export function findBrandsInName(name: string): Brand[] {
  if (!name) return [];
  const norm = normalizeDisplayName(name);
  const out = findBrands(norm, true);
  const collapsed = nameSkeleton(norm);
  const tokens = norm.split(' ').map(nameSkeleton).filter((t) => t.length >= 5);
  for (const { brand, skel } of FUZZY_NAMES) {
    if (out.includes(brand)) continue;
    const hit =
      collapsed.includes(skel) ||
      tokens.some((t) => t !== skel && t[0] === skel[0] && Math.abs(t.length - skel.length) <= 1 && editDistance(t, skel) <= 1);
    if (hit) out.push(brand);
  }
  return out;
}

/** Brands hidden in text whose words were split apart ("Lin ked i n Busi ne ss"). */
export function findBrandsCollapsed(text: string): Brand[] {
  const skel = nameSkeleton(text.slice(0, 3000));
  const out: Brand[] = [];
  for (const { brand, skel: s } of FUZZY_NAMES) if (!out.includes(brand) && skel.includes(s)) out.push(brand);
  return out;
}

export function isBrandDomain(brand: Brand, regDomain: string | null | undefined): boolean {
  if (!regDomain) return false;
  const d = regDomain.toLowerCase();
  return brand.domains.some((bd) => d === bd || d.endsWith('.' + bd));
}
