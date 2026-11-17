/* Dependency Check: provider fingerprints, question sets and fix library.
   Everything here is plain data so it's easy to review and extend via pull request. */
"use strict";

window.DC = {};

/* ---------- DNS fingerprints ----------
   Each entry: [regex tested against the record value, provider name, category key] */
DC.NS = [
  [/domaincontrol\.com\.?$/i, "GoDaddy DNS"],
  [/awsdns/i, "Amazon Route 53"],
  [/\.ns\.cloudflare\.com\.?$/i, "Cloudflare DNS"],
  [/googledomains\.com|ns-cloud-[a-z]\d*\.googledomains|ns-cloud/i, "Google Cloud DNS"],
  [/azure-dns\./i, "Azure DNS"],
  [/nsone\.net/i, "NS1"],
  [/registrar-servers\.com/i, "Namecheap DNS"],
  [/wixdns\.net/i, "Wix DNS"],
  [/squarespacedns\.com|squarespace/i, "Squarespace DNS"],
  [/dnsimple/i, "DNSimple"],
  [/ultradns/i, "UltraDNS"],
  [/dnsmadeeasy/i, "DNS Made Easy"],
  [/hostgator/i, "HostGator DNS"],
  [/bluehost/i, "Bluehost DNS"],
  [/name-services\.com|enom/i, "eNom DNS"],
  [/networksolutions|worldnic/i, "Network Solutions DNS"],
  [/hover\.com/i, "Hover DNS"],
  [/digitalocean/i, "DigitalOcean DNS"],
  [/linode/i, "Akamai/Linode DNS"],
  [/akam\.net|akamai/i, "Akamai DNS"],
  [/dynect|dyn\.com/i, "Oracle Dyn"],
  [/vercel-dns/i, "Vercel DNS"],
  [/netlify/i, "Netlify DNS"],
  [/shopify/i, "Shopify DNS"],
  [/ionos|ui-dns/i, "IONOS DNS"],
  [/porkbun/i, "Porkbun DNS"],
  [/gandi/i, "Gandi DNS"],
  [/dreamhost/i, "DreamHost DNS"],
  [/siteground/i, "SiteGround DNS"]
];

DC.MX = [
  [/aspmx\.l\.google\.com|googlemail\.com|smtp\.google\.com/i, "Google Workspace", "identity"],
  [/mail\.protection\.outlook\.com|outlook\.com/i, "Microsoft 365", "identity"],
  [/pphosted\.com/i, "Proofpoint (email filtering)", "email"],
  [/ppe-hosted\.com/i, "Proofpoint Essentials (email filtering)", "email"],
  [/mimecast/i, "Mimecast (email filtering)", "email"],
  [/barracudanetworks/i, "Barracuda (email filtering)", "email"],
  [/messagelabs|symantec/i, "Broadcom Email Security", "email"],
  [/zoho/i, "Zoho Mail", "identity"],
  [/secureserver\.net/i, "GoDaddy Email", "email"],
  [/messagingengine\.com/i, "Fastmail", "email"],
  [/protonmail/i, "Proton Mail", "email"],
  [/icloud\.com/i, "iCloud Mail", "email"],
  [/yahoodns/i, "Yahoo Mail", "email"],
  [/emailsrvr\.com/i, "Rackspace Email", "email"],
  [/mx\.cloudflare\.net/i, "Cloudflare Email Routing", "email"],
  [/improvmx/i, "ImprovMX (forwarding)", "email"],
  [/titan\.email/i, "Titan Email", "email"],
  [/ovh/i, "OVH Mail", "email"]
];

/* SPF include: / redirect= targets */
DC.SPF = [
  [/_spf\.google\.com/i, "Google Workspace", "identity"],
  [/spf\.protection\.outlook\.com/i, "Microsoft 365", "identity"],
  [/servers\.mcsv\.net|mailchimp/i, "Mailchimp", "marketing"],
  [/mandrillapp/i, "Mailchimp Transactional", "marketing"],
  [/sendgrid\.net/i, "SendGrid", "sending"],
  [/mailgun\.org/i, "Mailgun", "sending"],
  [/amazonses\.com/i, "Amazon SES", "sending"],
  [/spf\.mtasv\.net/i, "Postmark", "sending"],
  [/sparkpostmail/i, "SparkPost", "sending"],
  [/_spf\.salesforce\.com|exacttarget/i, "Salesforce", "crm"],
  [/hubspotemail\.net|hubspot/i, "HubSpot", "crm"],
  [/zendesk/i, "Zendesk", "support"],
  [/freshdesk|freshworks/i, "Freshworks", "support"],
  [/helpscout/i, "Help Scout", "support"],
  [/intercom/i, "Intercom", "support"],
  [/constantcontact/i, "Constant Contact", "marketing"],
  [/klaviyo/i, "Klaviyo", "marketing"],
  [/shopify/i, "Shopify", "web"],
  [/squarespace/i, "Squarespace", "web"],
  [/wix/i, "Wix", "web"],
  [/zoho/i, "Zoho", "crm"],
  [/qualtrics/i, "Qualtrics", "saas"],
  [/docusign/i, "DocuSign", "saas"],
  [/atlassian/i, "Atlassian", "saas"],
  [/mailjet/i, "Mailjet", "sending"],
  [/sendinblue|brevo/i, "Brevo", "marketing"],
  [/secureserver\.net/i, "GoDaddy Email", "email"],
  [/emailsrvr\.com/i, "Rackspace Email", "email"],
  [/pphosted\.com/i, "Proofpoint", "email"],
  [/ppe-hosted\.com/i, "Proofpoint Essentials (email filtering)", "email"],
  [/mimecast/i, "Mimecast", "email"],
  [/intuit|quickbooks/i, "Intuit QuickBooks", "finance"],
  [/bill\.com/i, "BILL", "finance"],
  [/gusto/i, "Gusto", "payroll"],
  [/adp\.com/i, "ADP", "payroll"],
  [/paychex/i, "Paychex", "payroll"],
  [/ringcentral/i, "RingCentral", "phone"],
  [/zoom\.us/i, "Zoom", "phone"]
];

/* TXT verification tokens on the apex */
DC.TXT = [
  [/^google-site-verification=/i, "Google", "identity"],
  [/^MS=ms\d+/i, "Microsoft 365", "identity"],
  [/^atlassian-domain-verification=/i, "Atlassian (Jira/Confluence)", "saas"],
  [/^docusign=/i, "DocuSign", "saas"],
  [/^adobe-idp-site-verification=|^adobe-sign-verification=/i, "Adobe", "saas"],
  [/^apple-domain-verification=/i, "Apple Business", "saas"],
  [/^facebook-domain-verification=/i, "Meta Business", "marketing"],
  [/^stripe-verification=/i, "Stripe", "payments"],
  [/^ZOOM_verify_/i, "Zoom", "phone"],
  [/^slack-domain-verification=/i, "Slack", "chat"],
  [/^dropbox-domain-verification=/i, "Dropbox", "files"],
  [/^box-domain-verification=/i, "Box", "files"],
  [/^hubspot-developer-verification=|^hubspot-domain-verification=/i, "HubSpot", "crm"],
  [/^pardot\d*=|^salesforce/i, "Salesforce", "crm"],
  [/^webexdomainverification|^cisco-ci-domain-verification=/i, "Cisco Webex", "phone"],
  [/^knowbe4-site-verification=/i, "KnowBe4", "saas"],
  [/^miro-verification=/i, "Miro", "saas"],
  [/^canva-site-verification=/i, "Canva", "saas"],
  [/^openai-domain-verification=/i, "OpenAI", "saas"],
  [/^anthropic-domain-verification/i, "Anthropic", "saas"],
  [/^zapier-domain-verification/i, "Zapier", "saas"],
  [/^onetrust-domain-verification=/i, "OneTrust", "saas"],
  [/^1password-site-verification=|^1password/i, "1Password", "saas"],
  [/^lastpass-verification/i, "LastPass", "saas"],
  [/^citrix-verification-code=/i, "Citrix", "saas"],
  [/^shopify-verification/i, "Shopify", "web"],
  [/^yandex-verification=/i, "Yandex", "marketing"],
  [/^globalsign-domain-verification=|^_globalsign/i, "GlobalSign (certificates)", "saas"],
  [/^mailru-verification/i, "Mail.ru", "marketing"],
  [/^notion-domain-verification/i, "Notion", "saas"],
  [/^calendly-site-verification/i, "Calendly", "saas"],
  [/^twilio-domain-verification/i, "Twilio", "phone"],
  [/^mongodb-site-verification/i, "MongoDB Atlas", "saas"],
  [/^github-verification|^_github/i, "GitHub", "saas"],
  [/^intuit-domain-verification/i, "Intuit", "finance"],
  [/^wrike-verification/i, "Wrike", "saas"],
  [/^asana-verification/i, "Asana", "saas"],
  [/^smartsheet-site-validation/i, "Smartsheet", "saas"],
  [/^segment-site-verification/i, "Segment", "saas"],
  [/^amazonses:/i, "Amazon SES", "sending"],
  [/^brevo-code:|^sendinblue-code:/i, "Brevo", "marketing"],
  [/^klaviyo-site-verification/i, "Klaviyo", "marketing"],
  [/^mandrill_verify/i, "Mailchimp Transactional", "marketing"]
];

/* Website host, matched against the CNAME chain of www.<domain> (and the apex) */
DC.WEB = [
  [/shops\.myshopify\.com|myshopify/i, "Shopify"],
  [/squarespace/i, "Squarespace"],
  [/wixdns|wix\.com/i, "Wix"],
  [/vercel/i, "Vercel"],
  [/netlify/i, "Netlify"],
  [/github\.io/i, "GitHub Pages"],
  [/amplifyapp\.com/i, "AWS Amplify"],
  [/cloudfront\.net/i, "Amazon CloudFront"],
  [/elb\.amazonaws\.com|amazonaws\.com/i, "Amazon Web Services"],
  [/azurewebsites|azureedge|azurefd|trafficmanager/i, "Microsoft Azure"],
  [/herokudns|herokuapp/i, "Heroku"],
  [/wpengine/i, "WP Engine"],
  [/kinsta/i, "Kinsta"],
  [/godaddysites|secureserver/i, "GoDaddy Website Builder"],
  [/hubspot|hs-sites/i, "HubSpot CMS"],
  [/webflow/i, "Webflow"],
  [/ghs\.googlehosted|ghs\.google/i, "Google Sites"],
  [/fastly/i, "Fastly"],
  [/akamai|edgekey|edgesuite/i, "Akamai"],
  [/cdn\.cloudflare|cloudflare/i, "Cloudflare"],
  [/pantheon/i, "Pantheon"],
  [/flywheel/i, "Flywheel"],
  [/weebly/i, "Weebly"],
  [/duda/i, "Duda"],
  [/bigcommerce/i, "BigCommerce"]
];

/* ---------- Categories ---------- */
DC.CATS = {
  identity:  { label: "Email + sign-in", impact: 3, note: "Usually the master key: if it's down or you're locked out, everything behind it goes with it." },
  email:     { label: "Email",           impact: 2 },
  dns:       { label: "DNS hosting",     impact: 3, note: "If DNS fails, email and the website both disappear." },
  web:       { label: "Website",         impact: 1 },
  sending:   { label: "Email sending",   impact: 1 },
  marketing: { label: "Marketing",       impact: 0 },
  crm:       { label: "CRM",             impact: 2 },
  support:   { label: "Customer support",impact: 1 },
  saas:      { label: "SaaS tool",       impact: 1 },
  payments:  { label: "Payments",        impact: 3 },
  phone:     { label: "Phones / meetings", impact: 2 },
  chat:      { label: "Team chat",       impact: 1 },
  files:     { label: "File storage",    impact: 2 },
  finance:   { label: "Accounting",      impact: 1 },
  payroll:   { label: "Payroll",         impact: 1 },
  isp:       { label: "Internet service",impact: 3 },
  lob:       { label: "Core business app", impact: 3 },
  it:        { label: "IT support",      impact: 1 },
  security:  { label: "Security agent",  impact: 2 },
  backup:    { label: "Backups",         impact: 1 },
  passwords: { label: "Password manager",impact: 2 },
  other:     { label: "Other",           impact: 1 }
};

/* Things DNS can't see. Checked ones become dependencies. */
DC.MANUAL = [
  { name: "Internet service (ISP)", cat: "isp" },
  { name: "Payments / card processing / POS", cat: "payments" },
  { name: "Core business app (practice mgmt, ERP, scheduling)", cat: "lob" },
  { name: "Phone system / VoIP", cat: "phone" },
  { name: "Accounting (QuickBooks, Xero…)", cat: "finance" },
  { name: "Payroll (Gusto, ADP…)", cat: "payroll" },
  { name: "Shared files (OneDrive, Google Drive, Dropbox)", cat: "files" },
  { name: "Password manager", cat: "passwords" },
  { name: "IT support provider / MSP", cat: "it" },
  { name: "Antivirus / EDR agent", cat: "security" },
  { name: "Backup service", cat: "backup" },
  { name: "Online store / booking site", cat: "web" },
  { name: "Team chat (Slack, Teams)", cat: "chat" }
];

/* ---------- Per-dependency questions ---------- */
DC.IMPACT = [
  { v: 3, label: "Business stops" },
  { v: 2, label: "Major slowdown" },
  { v: 1, label: "Annoying, we deal with it" },
  { v: 0, label: "Barely notice" }
];
DC.FALLBACK = [
  { v: "none", label: "No fallback", f: 1 },
  { v: "untested", label: "A plan, never tested", f: 0.55 },
  { v: "tested", label: "Tested fallback", f: 0.15 }
];
DC.ADMINS = [
  { v: "one", label: "One person", f: 0.85 },
  { v: "unknown", label: "Not sure", f: 1 },
  { v: "two", label: "Two+, recovery codes saved", f: 0.15 }
];

/* ---------- Business-wide questions ---------- */
DC.COSTS = [
  { v: "1", label: "Under $1,000", text: "under $1,000" },
  { v: "2", label: "$1,000 – $5,000", text: "$1,000–$5,000" },
  { v: "3", label: "$5,000 – $25,000", text: "$5,000–$25,000" },
  { v: "4", label: "Over $25,000", text: "over $25,000" }
];

DC.GLOBALS = [
  { id: "registrar", text: "Your domain registrar account has 2-step login, and at least two people can get into it.", help: "Whoever controls the registrar controls your email and website. Hijacked registrar accounts are a common way businesses lose their domain." },
  { id: "autorenew", text: "Your domain is set to auto-renew, with a payment method that won't expire soon.", help: "An expired domain takes email and the website offline at once." },
  { id: "breakglass", text: "There's an emergency admin account for email/sign-in, with recovery codes stored offline.", help: "For when the normal admin is locked out, gone, or the sign-in system is acting up." },
  { id: "backups", text: "Critical data has a backup an attacker or outage can't touch (offline or immutable), and you've test-restored it in the last year.", help: "A backup you've never restored is a hope, not a backup." },
  { id: "saasbackup", text: "Cloud email and files (Microsoft 365 / Google Workspace) are backed up by a separate service.", help: "The provider keeps the service running. Recovering your deleted or encrypted data is mostly on you." },
  { id: "oob", text: "You have a backup way to reach staff if email, chat and phones are down (a Signal group, a text tree).", help: "" },
  { id: "offline", text: "There's an offline copy of key contacts, vendor support numbers, account IDs and 'who to call'.", help: "Printed or on a phone. Not stored only in the system that's down." },
  { id: "isp", text: "You have backup internet (a cellular hotspot or failover router).", help: "" },
  { id: "drill", text: "You've walked through an 'X is down' scenario as a team in the last 12 months.", help: "Even 30 minutes around a table counts." }
];
DC.YESNO = [
  { v: "", label: "Choose…" },
  { v: "yes", label: "Yes" },
  { v: "no", label: "No" },
  { v: "unsure", label: "Not sure" }
];

/* ---------- Cost bands ---------- */
DC.COST = {
  free: { label: "Free", note: "time only", w: 1 },
  low:  { label: "$",    note: "under ~$50/mo", w: 1.35 },
  mid:  { label: "$$",   note: "~$50–$300/mo", w: 1.9 },
  high: { label: "$$$",  note: "project budget", w: 2.6 }
};
