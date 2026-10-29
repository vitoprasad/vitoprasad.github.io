/* GTM stack scanner engine.
 *
 * Reads a company's public DNS and names the go-to-market tools it can see:
 * marketing automation, sales tools, AI tools, website, events, support, and
 * the email setup underneath. Every finding keeps the record it came from.
 *
 * Runs unchanged in a browser (window.StackEngine) and in Node 18+ (require),
 * so the published dataset and a visitor's live scan come from the same code.
 */
(function (root) {
"use strict";

const api = {};

/* ---------- DNS over HTTPS ---------- */

const DOH_PRIMARY = "https://dns.google/resolve";
const DOH_FALLBACK = "https://cloudflare-dns.com/dns-query";
const TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16 };
const MAX_SPF_QUERIES = 30;
api.TYPE = TYPE;

function sourceUrl(name, type) {
  return DOH_PRIMARY + "?name=" + encodeURIComponent(name) + "&type=" + type;
}
api.sourceUrl = sourceUrl;

async function fetchJson(url, headers) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 9000);
  try {
    const response = await fetch(url, { headers: headers || {}, signal: controller.signal });
    if (!response.ok) throw new Error("HTTP " + response.status);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

// The resolver can be swapped (tests feed canned answers through it).
// It takes (name, type) and returns { Status, Answer } like Google's JSON API.
api.resolve = async function (name, type) {
  try {
    return { data: await fetchJson(sourceUrl(name, type)), url: sourceUrl(name, type) };
  } catch (first) {
    await new Promise(r => setTimeout(r, 400));
    try {
      return { data: await fetchJson(sourceUrl(name, type)), url: sourceUrl(name, type) };
    } catch (second) {
      const url = DOH_FALLBACK + "?name=" + encodeURIComponent(name) + "&type=" + type;
      return { data: await fetchJson(url, { accept: "application/dns-json" }), url: url };
    }
  }
};

// One DNS question. Returns the raw answer plus where it came from, so every
// conclusion can be traced back to a record.
async function ask(name, type, log) {
  const entry = { name: name, type: type, url: sourceUrl(name, type), status: null, answers: [], error: null };
  try {
    const got = await api.resolve(name, type);
    entry.url = got.url || entry.url;
    entry.status = got.data.Status;
    entry.answers = (got.data.Answer || []).map(a => ({ type: a.type, data: String(a.data) }));
  } catch (error) {
    entry.error = String(error && error.message || error);
  }
  if (log) log.push(entry);
  return entry;
}

function txtStrings(entry) {
  return entry.answers.filter(a => a.type === TYPE.TXT).map(a => joinTxt(a.data));
}

// Some resolvers return TXT data as quoted chunks ("abc" "def"). Join them.
function joinTxt(data) {
  const trimmed = data.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  const parts = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(trimmed)) !== null) parts.push(m[1].replace(/\\(.)/g, "$1"));
  return parts.join("");
}

function cnameChain(entry) {
  return entry.answers.filter(a => a.type === TYPE.CNAME).map(a => a.data.replace(/\.$/, "").toLowerCase());
}

async function pool(items, size, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const index = next++;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, run));
  return results;
}
api.pool = pool;

/* ---------- Parsing ---------- */

function cleanDomain(raw) {
  let d = String(raw || "").trim().toLowerCase();
  if (d.includes("@") && !d.includes("/")) d = d.split("@").pop();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").replace(/[\/?#].*$/, "").replace(/:\d+$/, "").replace(/\.$/, "");
  return d;
}

function validDomain(d) {
  return /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(d);
}
api.cleanDomain = cleanDomain;
api.validDomain = validDomain;

// A pasted list may be bare domains, URLs, emails, or "Company, domain" rows.
api.parseList = function (text) {
  const seen = new Set();
  const rows = [];
  String(text || "").split(/\r?\n/).forEach(line => {
    const cells = line.split(/[,\t;]/).map(s => s.trim()).filter(Boolean);
    if (!cells.length) return;
    let domain = null, name = null;
    for (const cell of cells) {
      const d = cleanDomain(cell);
      if (!domain && validDomain(d)) domain = d;
      else if (!name && !/[.@]/.test(cell)) name = cell;
    }
    if (domain && !seen.has(domain)) { seen.add(domain); rows.push({ domain: domain, name: name || domain }); }
  });
  return rows;
};

// A record is SPF only when it starts with "v=spf1" (RFC 7208, 4.5).
function isSpf(record) { return /^v=spf1(\s|$)/i.test(record); }
function looksLikeSpf(record) { return /v=spf1/i.test(record) && !isSpf(record); }

function parseTags(record) {
  const tags = {};
  record.split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  });
  return tags;
}

function mailtoDomains(value) {
  if (!value) return [];
  return value.split(",").map(s => s.trim().replace(/^mailto:/i, "").replace(/!.*$/, ""))
    .filter(Boolean).map(addr => addr.split("@").pop().toLowerCase());
}

/* ---------- Categories ---------- */

const CATEGORIES = [
  "Marketing automation", "Newsletter tools", "Sales tools", "CRM", "Content and landing pages", "Website", "Events and webinars",
  "Training and community", "Support and docs", "Trust and status pages", "Partner programs", "AI tools",
  "Data and analytics", "Email senders", "Mailbox", "Email security", "Work apps", "Security and IT", "Developer tools"
];
api.CATEGORIES = CATEGORIES;

/* ---------- Fingerprints ---------- */
// Hostname rules: [pattern, vendor, category]. A string matches as a substring
// of a hostname; a RegExp is tested against it. Hostnames come from CNAMEs on
// the company's subdomains, SPF includes, DKIM key CNAMEs, and MX records.

const HOST_RULES = [
  // Marketing automation
  [/(^|\.)mktoweb\.com$/, "Marketo", "Marketing automation"], ["mktossl.com", "Marketo", "Marketing automation"],
  [/(^|\.)mkto-[a-z]+\d+\.com$/, "Marketo", "Marketing automation"], ["mktomail.com", "Marketo", "Marketing automation"],
  ["mktdns.com", "Marketo", "Marketing automation"],
  ["pardot.com", "Pardot (Salesforce)", "Marketing automation"],
  ["exacttarget.com", "Salesforce Marketing Cloud", "Marketing automation"], ["exct.net", "Salesforce Marketing Cloud", "Marketing automation"],
  ["marketingcloudapps.com", "Salesforce Marketing Cloud", "Marketing automation"],
  ["sites.hubspot.net", "HubSpot", "Marketing automation"], ["hubspotemail.net", "HubSpot", "Marketing automation"],
  ["hs-sites.com", "HubSpot", "Marketing automation"], ["hubspotlinks.com", "HubSpot", "Marketing automation"],
  [/(^|\.)hubspot\.net$/, "HubSpot", "Marketing automation"], ["hscoscdn", "HubSpot", "Marketing automation"], ["_spf.hubspot", "HubSpot", "Marketing automation"],
  ["eloqua.com", "Oracle Eloqua", "Marketing automation"], ["en25.com", "Oracle Eloqua", "Marketing automation"],
  ["customeriomail.com", "Customer.io", "Marketing automation"], ["customer.io", "Customer.io", "Marketing automation"],
  ["iterable.com", "Iterable", "Marketing automation"], ["braze.com", "Braze", "Marketing automation"],
  ["braze.eu", "Braze", "Marketing automation"], ["appboy.com", "Braze", "Marketing automation"],
  ["klaviyomail.com", "Klaviyo", "Marketing automation"], ["klaviyo", "Klaviyo", "Marketing automation"],
  ["mcsv.net", "Mailchimp", "Newsletter tools"], ["list-manage.com", "Mailchimp", "Newsletter tools"],
  ["createsend", "Campaign Monitor", "Newsletter tools"], ["cmail", "Campaign Monitor", "Newsletter tools"],
  ["act-on.net", "Act-On", "Marketing automation"], ["actonsoftware.com", "Act-On", "Marketing automation"],
  ["activehosted.com", "ActiveCampaign", "Marketing automation"], ["acems", "ActiveCampaign", "Marketing automation"],
  ["sendinblue.com", "Brevo", "Newsletter tools"], ["brevo.com", "Brevo", "Newsletter tools"],
  ["constantcontact.com", "Constant Contact", "Newsletter tools"], ["conversion.ai", "Conversion", "Marketing automation"],
  ["knak.io", "Knak", "Marketing automation"],
  // Sales tools
  ["outrch.com", "Outreach", "Sales tools"], ["salesloft.com", "Salesloft", "Sales tools"],
  ["toutapp.com", "Marketo Sales Connect", "Sales tools"], ["nooks.in", "Nooks", "Sales tools"],
  ["apollo.io", "Apollo", "Sales tools"], ["gtmbuddy.io", "GTM Buddy", "Sales tools"],
  ["highspot.com", "Highspot", "Sales tools"], ["seismic.com", "Seismic", "Sales tools"],
  ["reachdesk.com", "Reachdesk", "Sales tools"], ["sendoso.com", "Sendoso", "Sales tools"],
  ["chilipiper.com", "Chili Piper", "Sales tools"], ["qualified.com", "Qualified", "Sales tools"],
  // CRM
  ["_spf.salesforce.com", "Salesforce", "CRM"], ["custdkim.salesforce.com", "Salesforce", "CRM"],
  ["siteforce.com", "Salesforce", "CRM"], [/(^|\.)force\.com$/, "Salesforce", "CRM"],
  ["dynamics.com", "Microsoft Dynamics", "CRM"], ["zcsend.net", "Zoho CRM", "CRM"],
  // Content and landing pages
  ["unbouncepages.com", "Unbounce", "Content and landing pages"], ["pageserve.co", "Instapage", "Content and landing pages"],
  ["lpages.co", "Leadpages", "Content and landing pages"], ["pathfactory.com", "PathFactory", "Content and landing pages"],
  ["folloze.com", "Folloze", "Content and landing pages"], ["userled.io", "Userled", "Content and landing pages"],
  ["uberflip.com", "Uberflip", "Content and landing pages"], ["casted.us", "Casted", "Content and landing pages"],
  ["flippingbook.com", "FlippingBook", "Content and landing pages"], ["turtl.co", "Turtl", "Content and landing pages"],
  ["navattic.com", "Navattic", "Content and landing pages"], ["storylane.io", "Storylane", "Content and landing pages"],
  // Website (only counted on marketing-facing subdomains, see WEBSITE_SUBS)
  ["webflow.com", "Webflow", "Website"], ["wpeproxy.com", "WP Engine", "Website"], ["wpengine.com", "WP Engine", "Website"],
  ["wpvip.com", "WordPress VIP", "Website"], ["kinsta", "Kinsta", "Website"], ["pantheonsite.io", "Pantheon", "Website"],
  ["acquia-sites.com", "Acquia", "Website"], ["adobeaemcloud.com", "Adobe Experience Manager", "Website"],
  ["framer.app", "Framer", "Website"], ["framer.website", "Framer", "Website"], ["framerusercontent", "Framer", "Website"],
  ["squarespace.com", "Squarespace", "Website"], ["wixdns.net", "Wix", "Website"], ["vercel-dns", "Vercel", "Website"],
  ["netlify", "Netlify", "Website"], ["sitecorecloud", "Sitecore", "Website"], ["contentstack", "Contentstack", "Website"],
  // Events and webinars
  ["goldcast.io", "Goldcast", "Events and webinars"], ["swoogo.com", "Swoogo", "Events and webinars"],
  ["cvent", "Cvent", "Events and webinars"], ["rainfocus.com", "RainFocus", "Events and webinars"],
  ["bizzabo.com", "Bizzabo", "Events and webinars"], ["bigmarker.com", "BigMarker", "Events and webinars"],
  ["zuddl.com", "Zuddl", "Events and webinars"], ["on24.com", "ON24", "Events and webinars"],
  ["events-branding.zoom.us", "Zoom Events", "Events and webinars"], ["splashthat.com", "Splash", "Events and webinars"],
  ["gatsby.events", "Gatsby", "Events and webinars"], ["hopin.com", "Hopin", "Events and webinars"],
  ["livestorm.co", "Livestorm", "Events and webinars"], ["airmeet.com", "Airmeet", "Events and webinars"],
  ["eventbrite", "Eventbrite", "Events and webinars"], ["luma-dns", "Luma", "Events and webinars"],
  // Training and community
  ["skilljarapp.com", "Skilljar", "Training and community"], ["skilljar.com", "Skilljar", "Training and community"],
  ["thinkific.com", "Thinkific", "Training and community"], ["docebosaas.com", "Docebo", "Training and community"],
  ["intellum.com", "Intellum", "Training and community"], ["thoughtindustries", "Thought Industries", "Training and community"],
  ["workramp.io", "WorkRamp", "Training and community"], ["northpass.com", "Northpass", "Training and community"],
  ["learnupon.com", "LearnUpon", "Training and community"], ["absorblms.com", "Absorb", "Training and community"],
  ["insided.com", "Gainsight Community (inSided)", "Training and community"], ["lithium.com", "Khoros", "Training and community"],
  ["khoros.com", "Khoros", "Training and community"], ["hosted-by-discourse.com", "Discourse", "Training and community"],
  ["discourse.group", "Discourse", "Training and community"], ["circle.so", "Circle", "Training and community"],
  ["bettermode", "Bettermode", "Training and community"], ["onvanilla.net", "Vanilla (Higher Logic)", "Training and community"],
  ["learnworlds.com", "LearnWorlds", "Training and community"], ["gradual.us", "Gradual", "Training and community"],
  // Support and docs
  ["zendesk.com", "Zendesk", "Support and docs"], ["intercomhelpcenter.com", "Intercom", "Support and docs"],
  ["intercom.help", "Intercom", "Support and docs"], ["intercom.io", "Intercom", "Support and docs"],
  ["intercombeta.com", "Intercom", "Support and docs"], ["freshdesk.com", "Freshdesk", "Support and docs"],
  ["helpscout", "Help Scout", "Support and docs"], ["document360.io", "Document360", "Support and docs"],
  ["gitbook.io", "GitBook", "Support and docs"], ["readmessl.com", "ReadMe", "Support and docs"],
  ["readme.io", "ReadMe", "Support and docs"], ["mintlify", "Mintlify", "Support and docs"],
  ["redocly.app", "Redocly", "Support and docs"], ["kustomer", "Kustomer", "Support and docs"],
  ["usepylon.com", "Pylon", "Support and docs"], ["helpjuice.com", "Helpjuice", "Support and docs"],
  // Trust and status pages
  ["safebase.io", "SafeBase", "Trust and status pages"], ["vantatrust.com", "Vanta Trust Center", "Trust and status pages"],
  ["whistic.com", "Whistic", "Trust and status pages"], ["securitypal.com", "SecurityPal", "Trust and status pages"],
  ["wolfia.com", "Wolfia", "Trust and status pages"], ["trustcenter.drata", "Drata Trust Center", "Trust and status pages"],
  ["conveyor.com", "Conveyor", "Trust and status pages"], [/(^|\.)elb-conveyor-\d+\.aptible\.in$/, "Conveyor", "Trust and status pages"], ["stspg-customer.com", "Atlassian Statuspage", "Trust and status pages"],
  ["hostedstatus.com", "Atlassian Statuspage", "Trust and status pages"], ["statuspage.incident.io", "incident.io", "Trust and status pages"],
  ["rootly.com", "Rootly", "Trust and status pages"], ["statuspal.io", "Statuspal", "Trust and status pages"],
  ["sorryapp.com", "Sorry", "Trust and status pages"], ["betteruptime.com", "Better Stack", "Trust and status pages"],
  ["instatus.com", "Instatus", "Trust and status pages"],
  // Partner programs
  ["partnerlinks.io", "PartnerStack", "Partner programs"], ["grsm.io", "PartnerStack", "Partner programs"],
  ["impartner", "Impartner", "Partner programs"], ["partnerpage.io", "PartnerPage", "Partner programs"],
  ["allbound.com", "Allbound", "Partner programs"], ["crossbeam.com", "Crossbeam", "Partner programs"],
  // Data and analytics
  ["bnc.lt", "Branch", "Data and analytics"], ["bitly.com", "Bitly", "Data and analytics"],
  ["singular.net", "Singular", "Data and analytics"], ["onelink.me", "AppsFlyer", "Data and analytics"], ["appsflyer.com", "AppsFlyer", "Data and analytics"],
  // Email senders
  ["sendgrid.net", "SendGrid", "Email senders"], ["mailgun.org", "Mailgun", "Email senders"],
  ["amazonses.com", "Amazon SES", "Email senders"], ["mtasv.net", "Postmark", "Email senders"],
  ["sparkpostmail.com", "SparkPost", "Email senders"], ["mailjet.com", "Mailjet", "Email senders"],
  ["mandrillapp.com", "Mailchimp Transactional", "Email senders"], ["smtp2go", "SMTP2GO", "Email senders"],
  ["postmarkapp.com", "Postmark", "Email senders"],
  // Support desks and work tools that send mail (from SPF)
  ["mail.zendesk.com", "Zendesk", "Support and docs"], ["freshemail.io", "Freshdesk", "Support and docs"],
  ["helpscoutemail.com", "Help Scout", "Support and docs"],
  ["atlassian.net", "Atlassian", "Work apps"], ["docusign.net", "DocuSign", "Work apps"],
  ["service-now.com", "ServiceNow", "Work apps"], ["qualtrics.com", "Qualtrics", "Work apps"],
  ["greenhouse.io", "Greenhouse", "Work apps"], ["lever.co", "Lever", "Work apps"], ["ashbyhq.com", "Ashby", "Work apps"]
];

// Hosting vendors only describe the marketing site when they sit behind one of these.
const WEBSITE_SUBS = new Set(["www", "blog", "resources", "content", "pages", "lp", "try", "get", "learn", "info", "go", "news"]);

// Mail routing, from MX and SPF. [pattern, vendor, category]
const MX_RULES = [
  ["aspmx.l.google.com", "Google Workspace", "Mailbox"], ["googlemail.com", "Google Workspace", "Mailbox"],
  ["smtp.google.com", "Google Workspace", "Mailbox"],
  ["mail.protection.office365.us", "Microsoft 365", "Mailbox"], ["mail.protection.outlook.com", "Microsoft 365", "Mailbox"],
  ["pphosted.com", "Proofpoint", "Email security"], ["ppe-hosted.com", "Proofpoint Essentials", "Email security"],
  ["mimecast", "Mimecast", "Email security"], ["barracudanetworks.com", "Barracuda", "Email security"],
  ["iphmx.com", "Cisco Secure Email", "Email security"], ["messagelabs.com", "Symantec Email Security.cloud", "Email security"],
  ["mailcontrol.com", "Forcepoint", "Email security"], ["trendmicro", "Trend Micro", "Email security"],
  ["sophos.com", "Sophos", "Email security"], ["fireeyecloud.com", "Trellix", "Email security"],
  ["trellix", "Trellix", "Email security"], ["hornetsecurity.com", "Hornetsecurity", "Email security"],
  ["antispamcloud.com", "SpamExperts (N-able)", "Email security"], ["vadesecure.com", "Vade", "Email security"],
  ["checkpoint", "Check Point Harmony Email", "Email security"],
  ["zoho.", "Zoho Mail", "Mailbox"], ["secureserver.net", "GoDaddy", "Mailbox"], ["emailsrvr.com", "Rackspace", "Mailbox"],
  ["mail.icloud.com", "Apple iCloud", "Mailbox"], ["protonmail.ch", "Proton Mail", "Mailbox"],
  ["messagingengine.com", "Fastmail", "Mailbox"]
];

const SPF_MAIL_RULES = [
  ["_spf.google.com", "Google Workspace", "Mailbox"],
  ["spf.protection.office365.us", "Microsoft 365", "Mailbox"], ["spf.protection.outlook.com", "Microsoft 365", "Mailbox"],
  ["pphosted.com", "Proofpoint", "Email security"], ["mimecast", "Mimecast", "Email security"],
  ["mim.ec", "Mimecast", "Email security"], ["iphmx.com", "Cisco Secure Email", "Email security"],
  ["messagelabs.com", "Symantec Email Security.cloud", "Email security"],
  ["barracudanetworks.com", "Barracuda", "Email security"],
  ["vali.email", "Valimail", "Email security"], ["powerspf.com", "PowerDMARC", "Email security"],
  ["ondmarc.com", "Red Sift OnDMARC", "Email security"], ["autospf", "AutoSPF", "Email security"]
];

const DMARC_RULES = [
  ["vali.email", "Valimail"], ["emaildefense.proofpoint.com", "Proofpoint Email Fraud Defense"],
  ["dmarcian", "dmarcian"], ["ondmarc.com", "Red Sift OnDMARC"], ["dmarcanalyzer.com", "Mimecast DMARC Analyzer"],
  ["agari.com", "Agari (Fortra)"], ["easydmarc", "EasyDMARC"], ["powerdmarc.com", "PowerDMARC"],
  ["report-uri.com", "Report URI"], ["postmarkapp.com", "Postmark DMARC"], ["uriports.com", "URIports"],
  ["dmarc-report.com", "MxToolbox"], ["mailhardener.com", "Mailhardener"], ["sendmarc.com", "Sendmarc"],
  ["fraudmarc.com", "Fraudmarc"], ["everest.email", "Validity"], ["returnpath.net", "Validity"],
  ["250ok.net", "Validity"], ["dmarc.mailgun.org", "Mailgun DMARC"], ["dmarc.cloudflare.net", "Cloudflare DMARC Management"],
  ["dmarc-reports.cloudflare.net", "Cloudflare DMARC Management"],
  ["skysnag", "Skysnag"], ["cyber.dhs.gov", "CISA (US government reporting)"]
];

// Domain verification records on the root domain: [regex on the record, vendor, category].
// A company publishes one when it connects its domain to a vendor, usually for
// single sign-on or a company workspace. They often stay after a contract ends,
// so they count as "verified", a weaker claim than "in use".
const TXT_RULES = [
  // AI tools
  [/^openai-domain-verification=/i, "OpenAI (ChatGPT)", "AI tools"],
  [/^anthropic-domain-verification-[a-z0-9]+=/i, "Anthropic (Claude)", "AI tools"],
  [/^cursor-domain-verification-[a-z0-9]+=/i, "Cursor", "AI tools"],
  [/^perplexity-ai-domain-verification-[a-z0-9]+=/i, "Perplexity", "AI tools"],
  [/^windsurf-verification=/i, "Windsurf", "AI tools"], [/^mistral-domain-verification=/i, "Mistral", "AI tools"],
  [/^gamma-domain-verification-[a-z0-9]+=/i, "Gamma", "AI tools"],
  [/^amp-by-sourcegraph-domain-verification-[a-z0-9]+=/i, "Amp (Sourcegraph)", "AI tools"],
  [/^gc-ai-domain-verification-[a-z0-9]+=/i, "GC AI", "AI tools"], [/^elevenlabs[=-]/i, "ElevenLabs", "AI tools"],
  [/^read-ai-verification=/i, "Read AI", "AI tools"], [/^fireflies-verification=/i, "Fireflies", "AI tools"],
  [/^decagon-domain-verification-[a-z0-9]+=/i, "Decagon", "AI tools"],
  [/^profound-domain-verification-[a-z0-9]+=/i, "Profound", "AI tools"],
  [/^juicebox-domain-verification-[a-z0-9]+=/i, "Juicebox", "AI tools"],
  [/^serval-domain-verification-[a-z0-9]+=/i, "Serval", "AI tools"],
  [/^glean-domain-verification/i, "Glean", "AI tools"], [/^writer-domain-verification/i, "Writer", "AI tools"],
  [/^lovable[_-](domain[_-])?verification/i, "Lovable", "AI tools"], [/^dust-domain-verification/i, "Dust", "AI tools"], [/^replit-verify/i, "Replit", "AI tools"],
  // Marketing and sales
  [/^hubspot-domain-verification=/i, "HubSpot", "Marketing automation"],
  [/^pardot\d+_?\d*=|^pardot_\d+_\*=/i, "Pardot (Salesforce)", "Marketing automation"],
  [/^SFMC-/i, "Salesforce Marketing Cloud", "Marketing automation"],
  [/^(brevo|sendinblue)-code:/i, "Brevo", "Newsletter tools"],
  [/^klaviyo-site-verification=/i, "Klaviyo", "Marketing automation"],
  [/^drift-domain-verification=/i, "Drift", "Sales tools"], [/^reachdesk-verification=/i, "Reachdesk", "Sales tools"],
  [/^lemlist-verif/i, "lemlist", "Sales tools"], [/^clay-domain-verification-[a-z0-9]+=/i, "Clay", "Sales tools"],
  [/^actively-ai-domain-verification-[a-z0-9]+=/i, "Actively", "Sales tools"],
  [/^artisan-domain-verification-[a-z0-9]+=/i, "Artisan", "Sales tools"],
  [/^attio-domain-verification=/i, "Attio", "CRM"],
  [/^segment-site-verification=/i, "Segment", "Data and analytics"],
  [/^liveramp-site-verification=/i, "LiveRamp", "Data and analytics"],
  [/^mixpanel-domain-verify=/i, "Mixpanel", "Data and analytics"], [/^pendo-domain-verification=/i, "Pendo", "Data and analytics"],
  [/^status-page-domain-verification=/i, "Atlassian Statuspage", "Trust and status pages"],
  [/^pylon-domain-verification-[a-z0-9]+=/i, "Pylon", "Support and docs"],
  [/^mgverify=/i, "Mailgun", "Email senders"], [/^amazonses:/i, "Amazon SES", "Email senders"],
  [/^easydmarc-verification/i, "EasyDMARC", "Email security"], [/^validity-domain-verification/i, "Validity", "Email security"],
  [/^virtru-site-verification/i, "Virtru", "Email security"],
  // Work apps
  [/^atlassian-(sending-)?domain-verification=/i, "Atlassian", "Work apps"], [/^zapier-domain-verification-challenge=/i, "Zapier", "Work apps"],
  [/^make-domain-verification/i, "Make", "Work apps"], [/^adobe-sign-verification/i, "Adobe", "Work apps"], [/^slack-domain-verification=/i, "Slack", "Work apps"],
  [/^(notion-domain-verification=|notion_verify_)/i, "Notion", "Work apps"],
  [/^(zoom-domain-verification\s*=|ZOOM_verify_)/i, "Zoom", "Work apps"], [/^MS=ms\d+/i, "Microsoft 365", "Work apps"],
  [/^docusign=/i, "DocuSign", "Work apps"], [/^adobe-idp-site-verification=/i, "Adobe", "Work apps"],
  [/^canva-site-verification=/i, "Canva", "Work apps"], [/^miro-verification=/i, "Miro", "Work apps"],
  [/^figma-domain-verification=/i, "Figma", "Work apps"], [/^linear-domain-verification=/i, "Linear", "Work apps"],
  [/^dropbox-domain-verification=/i, "Dropbox", "Work apps"], [/^box-domain-verification=/i, "Box", "Work apps"],
  [/^smartsheet-site-validation=/i, "Smartsheet", "Work apps"], [/^airtable-verification=/i, "Airtable", "Work apps"],
  [/^loom-(site-)?verification=/i, "Loom", "Work apps"], [/^whimsical=/i, "Whimsical", "Work apps"],
  [/^monday-com-verification=/i, "monday.com", "Work apps"], [/^wrike-verification=/i, "Wrike", "Work apps"],
  [/^coda-verification=/i, "Coda", "Work apps"], [/^lucid-verification=/i, "Lucid", "Work apps"],
  [/^asana-domain-verification/i, "Asana", "Work apps"], [/^calendly-site-verification=/i, "Calendly", "Work apps"],
  [/^cisco-ci-domain-verification=/i, "Webex", "Work apps"], [/^gather-domain-verification=/i, "Gather", "Work apps"],
  [/^rippling-domain-verification=/i, "Rippling", "Work apps"], [/^remote-domain-verification=/i, "Remote", "Work apps"],
  [/^carta-domain-verification-[a-z0-9]+=/i, "Carta", "Work apps"], [/^stripe-verification=/i, "Stripe", "Work apps"],
  [/^uber-domain-verification=/i, "Uber for Business", "Work apps"], [/^amazon-business-verification=/i, "Amazon Business", "Work apps"],
  // Security and IT
  [/^1password-site-verification=/i, "1Password", "Security and IT"], [/^jamf-site-verification=/i, "Jamf", "Security and IT"],
  [/^wiz-domain-verification=/i, "Wiz", "Security and IT"], [/^onetrust-domain-verification=/i, "OneTrust", "Security and IT"],
  [/^h1-domain-verification=/i, "HackerOne", "Security and IT"], [/^bugcrowd-verification=/i, "Bugcrowd", "Security and IT"],
  [/^paloaltonetworks-site-verification=/i, "Palo Alto Networks", "Security and IT"],
  [/^cloudflare_dashboard_sso=/i, "Cloudflare", "Security and IT"], [/^TAILSCALE-/i, "Tailscale", "Security and IT"],
  [/^duo_sso_verification=/i, "Duo", "Security and IT"], [/^knowbe4-site-verification=/i, "KnowBe4", "Security and IT"],
  [/^detectify-verification=/i, "Detectify", "Security and IT"], [/^apple-domain-verification=/i, "Apple Business Manager", "Security and IT"],
  [/^okta-verification=/i, "Okta", "Security and IT"], [/^sophos-domain-verification/i, "Sophos", "Security and IT"],
  [/^oneleet-domain-verification/i, "Oneleet", "Security and IT"], [/^parallels-domain-verification/i, "Parallels", "Security and IT"],
  [/^citrix-verification-code/i, "Citrix", "Security and IT"],
  // Developer tools
  [/^docker-verification=/i, "Docker", "Developer tools"], [/^jetbrains-domain-verification=/i, "JetBrains", "Developer tools"],
  [/^postman-domain-verification=/i, "Postman", "Developer tools"], [/^mongodb-site-verification=/i, "MongoDB", "Developer tools"],
  [/^twilio-domain-verification=/i, "Twilio", "Developer tools"], [/^heroku-domain-verification=/i, "Heroku", "Developer tools"],
  [/^launchdarkly-domain-verification=/i, "LaunchDarkly", "Developer tools"],
  [/^browserstack-domain-verification=/i, "BrowserStack", "Developer tools"],
  [/^vercel-domain-verification-[a-z0-9]+=/i, "Vercel", "Developer tools"],
  [/^hcp-domain-verification=/i, "HashiCorp", "Developer tools"], [/^anyscale-domain-verification/i, "Anyscale", "Developer tools"],
  [/^dynatrace-site-verification/i, "Dynatrace", "Developer tools"]
];

// DKIM selectors worth asking for. Vendor is named only where the selector is
// that vendor's own default; a CNAME behind the key names the vendor anyway.
const DKIM_SELECTORS = [
  ["google", "Google Workspace", "Mailbox"], ["selector1", "Microsoft 365", "Mailbox"], ["selector2", "Microsoft 365", "Mailbox"],
  ["s1", "SendGrid", "Email senders"], ["s2", "SendGrid", "Email senders"], ["smtpapi", "SendGrid", "Email senders"],
  ["k1", null, null], ["k2", null, null], ["mte1", "Mailchimp Transactional", "Email senders"],
  ["mte2", "Mailchimp Transactional", "Email senders"], ["200608", "Salesforce Marketing Cloud", "Marketing automation"],
  ["cm", "Campaign Monitor", "Newsletter tools"], ["hs1", "HubSpot", "Marketing automation"],
  ["hs2", "HubSpot", "Marketing automation"], ["sf1", "Salesforce", "CRM"], ["sf2", "Salesforce", "CRM"],
  ["kl", "Klaviyo", "Marketing automation"], ["kl2", "Klaviyo", "Marketing automation"],
  ["m1", null, null], ["pm", "Postmark", "Email senders"], ["mandrill", "Mailchimp Transactional", "Email senders"],
  ["zendesk1", "Zendesk", "Support and docs"], ["zendesk2", "Zendesk", "Support and docs"],
  ["ctct1", "Constant Contact", "Newsletter tools"], ["ctct2", "Constant Contact", "Newsletter tools"],
  ["mailjet", "Mailjet", "Email senders"], ["default", null, null]
];
api.DKIM_SELECTORS = DKIM_SELECTORS;

// Subdomains where companies point their go-to-market tools.
const SUBDOMAINS = [
  "www", "go", "info", "pages", "page", "lp", "get", "try", "hello", "learn", "engage", "marketing", "resources", "content",
  "email", "em", "e", "click", "t", "track", "trk", "link", "links", "news", "connect", "explore", "discover", "success",
  "events", "event", "webinar", "webinars", "academy", "university", "training", "community",
  "support", "help", "docs", "status", "trust", "security", "partners", "partner", "blog"
];
api.SUBDOMAINS = SUBDOMAINS;

function matchRule(host, table) {
  const h = host.toLowerCase();
  for (const row of table) {
    const p = row[0];
    if (p instanceof RegExp ? p.test(h) : h.includes(p)) return row;
  }
  return null;
}
api.matchRule = matchRule;

/* ---------- SPF walk ---------- */

// Follows include: and redirect= to count DNS lookups against the limit of 10
// (RFC 7208, 4.6.4) and to collect every service the record authorizes.
async function walkSpf(domain, rootRecord, log) {
  const state = { lookups: 0, includes: [], macros: [], errors: [], queries: 0, visited: new Set(),
                  redirectTarget: null, redirectAll: null };
  async function visit(name, depth) {
    if (state.visited.has(name) || state.queries >= MAX_SPF_QUERIES) return;
    state.visited.add(name);
    let records;
    if (depth === 0) {
      records = [rootRecord];
    } else {
      state.queries++;
      records = txtStrings(await ask(name, "TXT", log)).filter(isSpf);
    }
    if (!records.length) { state.errors.push(name); return; }
    const children = [];
    if (name === state.redirectTarget) {
      const ending = records[0].match(/\s([+\-~?]?)all\b/i);
      if (ending) state.redirectAll = (ending[1] || "+") + "all";
      else {
        const next = records[0].match(/\sredirect=(\S+)/i);
        if (next) state.redirectTarget = next[1].toLowerCase();
      }
    }
    if (depth === 0) {
      const redirect = records[0].match(/\sredirect=(\S+)/i);
      if (redirect && !/\s[+\-~?]?all\b/i.test(records[0])) state.redirectTarget = redirect[1].toLowerCase();
    }
    for (const term of records[0].split(/\s+/).slice(1)) {
      const t = term.replace(/^[+\-~?]/, "");
      const lower = t.toLowerCase();
      let target = null;
      if (lower.startsWith("include:")) target = t.slice(8);
      else if (lower.startsWith("redirect=")) target = t.slice(9);
      if (target !== null) {
        state.lookups++;
        state.includes.push({ host: target.toLowerCase(), depth: depth });
        if (target.includes("%{")) state.macros.push(target);
        else if (depth < 6) children.push(target.toLowerCase());
      } else if (/^(a|mx|ptr|exists)([:/]|$)/.test(lower)) {
        state.lookups++;
      }
    }
    for (const child of children) await visit(child, depth + 1);
  }
  await visit(domain, 0);
  return state;
}

/* ---------- One full read of a domain ---------- */

const WILDCARD_LABEL = "zq7x-not-a-real-host";

// Asks every question about one domain. Returns the raw answers only; turning
// them into vendors is analyze()'s job, so a later fix to the rules can be
// re-run over saved reads without asking DNS again.
async function readDomain(domain, opts) {
  const options = opts || {};
  const width = options.concurrency || 8;
  const log = [];
  let done = 0;
  const tick = () => { done++; if (options.onProgress) options.onProgress(done, api.questionCount()); };
  const counted = p => p.then(r => { tick(); return r; });

  const [mx, rootTxt, dmarc, mtaSts, bimi, wildHost, wildKey] = await Promise.all([
    ask(domain, "MX", log), ask(domain, "TXT", log), ask("_dmarc." + domain, "TXT", log),
    ask("_mta-sts." + domain, "TXT", log), ask("default._bimi." + domain, "TXT", log),
    ask(WILDCARD_LABEL + "." + domain, "A", log), ask(WILDCARD_LABEL + "._domainkey." + domain, "TXT", log)
  ].map(counted));

  const subs = await pool(SUBDOMAINS, width, async sub => {
    const entry = await counted(ask(sub + "." + domain, "A", log));
    return { sub: sub, chain: cnameChain(entry), status: entry.status };
  });
  const keys = await pool(DKIM_SELECTORS, width, async row => {
    const entry = await counted(ask(row[0] + "._domainkey." + domain, "TXT", log));
    const txt = txtStrings(entry).find(t => /(^|;)\s*(v=DKIM1|p=)/i.test(t) || /\bp=/.test(t));
    if (!txt) return null;
    const p = (parseTags(txt).p || "").trim();
    return { selector: row[0], revoked: p === "", cnames: cnameChain(entry), txt: txt };
  });

  const rootRecords = txtStrings(rootTxt);
  const spfRecords = rootRecords.filter(isSpf);
  const spfWalk = spfRecords.length ? await walkSpf(domain, spfRecords[0], log) : null;
  tick();

  const wildcardKey = txtStrings(wildKey).find(t => /\bp=/.test(t)) || null;
  return {
    domain: domain, at: new Date().toISOString(), log: log,
    mx: mx, rootRecords: rootRecords, spfRecords: spfRecords, decoys: rootRecords.filter(looksLikeSpf),
    spfWalk: spfWalk ? { lookups: spfWalk.lookups, includes: spfWalk.includes, macros: spfWalk.macros,
                         errors: spfWalk.errors, redirectAll: spfWalk.redirectAll } : null,
    dmarcRecords: txtStrings(dmarc).filter(t => /^v=DMARC1/i.test(t)),
    mtaSts: txtStrings(mtaSts).some(t => /^v=STSv1/i.test(t)),
    bimi: txtStrings(bimi).some(t => /^v=BIMI1/i.test(t)),
    wildcard: { chain: cnameChain(wildHost), resolves: wildHost.answers.length > 0, key: wildcardKey },
    subs: subs, dkim: keys.filter(Boolean).filter(k => !(wildcardKey && k.txt === wildcardKey && !k.cnames.length)),
    nxdomain: mx.status === 3 && rootTxt.status === 3,
    failed: [mx, rootTxt, dmarc].every(e => e.error)
  };
}
api.readDomain = readDomain;
api.questionCount = () => 8 + SUBDOMAINS.length + DKIM_SELECTORS.length;

/* ---------- Turning answers into a stack ---------- */

const POLICY_RANK = { missing: 0, none: 1, quarantine: 2, reject: 3 };
api.POLICY_RANK = POLICY_RANK;

function uniq(list) { return Array.from(new Set(list)); }

function analyze(read) {
  const d = read.domain;
  const own = h => h === d || h.endsWith("." + d);
  const vendors = new Map();

  // strength: "in use" when live mail or a live hostname depends on the vendor,
  // "verified" when the only trace is a domain verification record.
  function add(vendor, category, strength, kind, name, value) {
    if (!vendor || !category) return;
    const key = vendor + "|" + category;
    if (!vendors.has(key)) vendors.set(key, { vendor: vendor, category: category, strength: strength, evidence: [] });
    const v = vendors.get(key);
    if (strength === "in use") v.strength = "in use";
    if (!v.evidence.some(e => e.kind === kind && e.name === name && e.value === value) && v.evidence.length < 6) {
      v.evidence.push({ kind: kind, name: name, value: value });
    }
  }

  // Subdomain CNAMEs. Ignore anything that only exists because of a wildcard.
  const wildcardChain = read.wildcard && read.wildcard.chain.length ? read.wildcard.chain.join(">") : null;
  const liveSubs = [];
  read.subs.forEach(s => {
    if (!s.chain.length) return;
    if (wildcardChain && s.chain.join(">") === wildcardChain) return;
    const outside = s.chain.filter(h => !own(h));
    if (!outside.length) return;
    liveSubs.push({ sub: s.sub, target: outside[0] });
    for (const host of outside) {
      const r = matchRule(host, HOST_RULES);
      if (!r) continue;
      if (r[2] === "Website" && !WEBSITE_SUBS.has(s.sub)) break;
      add(r[1], r[2], "in use", "CNAME", s.sub + "." + d, host);
      if (r[1] === "HubSpot" && s.sub === "www") add("HubSpot CMS", "Website", "in use", "CNAME", s.sub + "." + d, host);
      break;
    }
  });

  // Mail servers.
  const mxHosts = read.mx.answers.filter(x => x.type === TYPE.MX)
    .map(x => x.data.split(/\s+/).pop().replace(/\.$/, "").toLowerCase()).sort();
  mxHosts.forEach(h => { const r = matchRule(h, MX_RULES); if (r) add(r[1], r[2], "in use", "MX", d, h); });

  // SPF includes.
  const includes = read.spfWalk ? read.spfWalk.includes : [];
  includes.forEach(i => {
    const r = matchRule(i.host, SPF_MAIL_RULES) || matchRule(i.host, HOST_RULES);
    if (r && r[2] !== "Website") add(r[1], r[2], "in use", "SPF", d, i.host);
  });

  // DKIM keys: the CNAME behind a key names its vendor; otherwise the selector hints.
  read.dkim.filter(k => !k.revoked).forEach(k => {
    const name = k.selector + "._domainkey." + d;
    const viaCname = k.cnames.map(c => c.includes("onmicrosoft.com") ? [c, "Microsoft 365", "Mailbox"] : matchRule(c, HOST_RULES))
      .find(Boolean);
    if (viaCname) { add(viaCname[1], viaCname[2], "in use", "DKIM", name, k.cnames[k.cnames.length - 1]); return; }
    const row = DKIM_SELECTORS.find(s => s[0] === k.selector);
    if (row && row[1]) add(row[1], row[2], "in use", "DKIM", name, "key published");
  });

  // DMARC report vendors.
  const dmarcTags = read.dmarcRecords[0] ? parseTags(read.dmarcRecords[0]) : null;
  const reportDomains = dmarcTags ? uniq(mailtoDomains(dmarcTags.rua).concat(mailtoDomains(dmarcTags.ruf))) : [];
  reportDomains.forEach(rd => {
    const r = matchRule(rd, DMARC_RULES);
    if (r) add(r[1], "Email security", "in use", "DMARC", "_dmarc." + d, rd);
  });

  // Domain verification records.
  read.rootRecords.forEach(t => {
    const r = TXT_RULES.find(row => row[0].test(t.trim()));
    if (r) add(r[1], r[2], "verified", "TXT", d, t.length > 80 ? t.slice(0, 77) + "..." : t);
  });

  // A tool with both a verification record and live use is simply in use.
  const list = Array.from(vendors.values());
  list.sort((x, y) => CATEGORIES.indexOf(x.category) - CATEGORIES.indexOf(y.category) ||
                      (x.strength === y.strength ? 0 : x.strength === "in use" ? -1 : 1) || x.vendor.localeCompare(y.vendor));

  // Posture.
  let policy = dmarcTags ? ((dmarcTags.p || "").toLowerCase() || "none") : "missing";
  if (!(policy in POLICY_RANK)) policy = "none";
  let pct = dmarcTags && dmarcTags.pct !== undefined ? parseInt(dmarcTags.pct, 10) : 100;
  if (isNaN(pct)) pct = 100;
  const spf = read.spfRecords[0] || null;
  const allTerm = spf ? spf.match(/\s([+\-~?]?)all\b/i) : null;
  const spfAll = !spf ? "missing" : allTerm ? (allTerm[1] || "+") + "all" :
                 (read.spfWalk && read.spfWalk.redirectAll) || (/redirect=/i.test(spf) ? "redirect" : "none");
  const inCat = (cat, strength) => list.filter(v => v.category === cat && (!strength || v.strength === strength)).map(v => v.vendor);

  const posture = {
    dmarc: policy, pct: policy === "missing" ? null : pct,
    dmarcRecords: read.dmarcRecords.length,
    reportVendors: uniq(reportDomains.map(rd => own(rd) ? "own team" : (matchRule(rd, DMARC_RULES) || [rd, rd])[1])),
    spf: spf ? "present" : "missing", spfRecords: read.spfRecords.length, spfAll: spfAll,
    spfLookups: read.spfWalk ? read.spfWalk.lookups : 0, spfHosted: !!(read.spfWalk && read.spfWalk.macros.length),
    dkimKeys: read.dkim.filter(k => !k.revoked).map(k => k.selector).sort(),
    mailbox: uniq(inCat("Mailbox", "in use").filter(v => mxHosts.some(h => { const r = matchRule(h, MX_RULES); return r && r[1] === v; }))),
    gateway: uniq(mxHosts.map(h => matchRule(h, MX_RULES)).filter(r => r && r[2] === "Email security").map(r => r[1])),
    mxHosts: mxHosts, mtaSts: read.mtaSts, bimi: read.bimi, decoySpf: read.decoys.length > 0
  };
  if (!posture.mailbox.length) posture.mailbox = uniq(inCat("Mailbox", "in use"));

  const a = { domain: d, at: read.at, vendors: list, posture: posture, liveSubs: liveSubs,
              wildcard: !!wildcardChain || !!(read.wildcard && read.wildcard.key) };
  a.signals = signalsFor(a);
  return a;
}
api.analyze = analyze;

/* ---------- Signals a GTM team would act on ---------- */

// [id, label]. Shared by the page's filters and the change log.
const SIGNALS = [
  ["two-maps", "Two marketing automation platforms"],
  ["spf-over", "SPF over the lookup limit"],
  ["spf-near", "SPF one or two tools from the limit"],
  ["bulk-no-dmarc", "Sends marketing mail with no DMARC"],
  ["dmarc-not-enforced", "DMARC not enforced"],
  ["no-map", "No marketing automation visible"]
];
api.SIGNALS = SIGNALS;

function platforms(a) {
  return uniq(a.vendors.filter(v => v.category === "Marketing automation" && v.strength === "in use").map(v => v.vendor));
}
api.platforms = platforms;

function signalsFor(a) {
  const out = [];
  const maps = platforms(a);
  const p = a.posture;
  if (maps.length >= 2) {
    out.push({ id: "two-maps", title: "Runs " + maps.length + " marketing automation platforms",
               detail: maps.join(" and ") + " are both live. Either a migration is in flight or teams run separate tools." });
  }
  if (p.spf === "present" && p.spfLookups > 10) {
    out.push({ id: "spf-over", title: "SPF needs " + p.spfLookups + " lookups, over the limit of 10",
               detail: "Receivers may stop partway and fail real mail. Any new sending tool makes it worse." });
  } else if (p.spf === "present" && p.spfLookups >= 9) {
    out.push({ id: "spf-near", title: "SPF uses " + p.spfLookups + " of 10 lookups",
               detail: "The next sending tool they add, a new marketing platform included, pushes SPF over the limit unless someone cleans it up." });
  }
  if (p.dmarc === "missing" && maps.length) {
    out.push({ id: "bulk-no-dmarc", title: "Sends marketing mail with no DMARC record",
               detail: "Gmail, Yahoo and Outlook now require DMARC from bulk senders, so campaigns from " + maps[0] + " are at risk of landing in spam or bouncing." });
  }
  if (p.dmarc === "none" || p.dmarc === "missing") {
    out.push({ id: "dmarc-not-enforced", title: p.dmarc === "missing" ? "No DMARC record" : "DMARC is in monitoring mode",
               detail: "Anyone can send mail that claims to be from this domain and still get delivered." });
  }
  if (!maps.length) {
    const verified = uniq(a.vendors.filter(v => v.category === "Marketing automation").map(v => v.vendor));
    const letters = uniq(a.vendors.filter(v => v.category === "Newsletter tools" && v.strength === "in use").map(v => v.vendor));
    out.push({ id: "no-map", title: "No marketing automation in use",
               detail: (verified.length ? verified.join(" and ") + (verified.length > 1 ? " have" : " has") + " the domain verified, but nothing live points at it. " : "") +
                       (letters.length ? "Mail goes out through " + letters.join(" and ") + ", a newsletter tool. " : "") +
                       "Either they run no platform, or theirs leaves no trace in DNS." });
  }
  return out;
}

/* ---------- Comparing two reads ---------- */

// What changed between two analyses of the same domain, worded for a sales team.
// Returns [severity, title, detail] rows. Severity: critical, high, medium, info.
function compare(prev, next) {
  const out = [];
  const key = v => v.vendor + "|" + v.category;
  const before = new Map(prev.vendors.map(v => [key(v), v]));
  const after = new Map(next.vendors.map(v => [key(v), v]));
  const wasLive = v => before.has(key(v)) && before.get(key(v)).strength === "in use";
  const isLive = v => after.has(key(v)) && after.get(key(v)).strength === "in use";
  // Live use counts apart from verification, so "verified, then live" is a start
  // and "live, then only verified" is a stop.
  const started = next.vendors.filter(v => v.strength === "in use" && !wasLive(v));
  const stopped = prev.vendors.filter(v => v.strength === "in use" && !isLive(v));
  const verifiedAdded = next.vendors.filter(v => v.strength === "verified" && !before.has(key(v)));
  const verifiedRemoved = prev.vendors.filter(v => v.strength === "verified" && !after.has(key(v)));

  const isMap = v => v.category === "Marketing automation";
  const mapsStarted = started.filter(isMap), mapsStopped = stopped.filter(isMap);
  const switched = mapsStarted.length && mapsStopped.length;
  if (switched) {
    out.push(["critical", "Marketing automation switch", "From " + mapsStopped.map(v => v.vendor).join(", ") + " to " +
              mapsStarted.map(v => v.vendor).join(", ") + "."]);
  }
  const severityFor = (v, adding) => {
    if (isMap(v) || v.category === "CRM") return v.strength === "in use" ? "high" : "medium";
    if (v.category === "Sales tools" || v.category === "AI tools") return adding ? "high" : "medium";
    if (["Email security", "Mailbox"].includes(v.category)) return "high";
    return v.strength === "in use" ? "medium" : "info";
  };
  const seenIn = v => { const e = v.evidence.find(x => x.kind !== "TXT") || v.evidence[0]; return "Seen in " + e.kind + " " + e.name + "."; };
  started.forEach(v => {
    if (switched && isMap(v)) return;
    out.push([severityFor(v, true), "Started using " + v.vendor, v.category + ". " + (before.has(key(v)) ? "The domain was already verified, now it is live. " : "") + seenIn(v)]);
  });
  stopped.forEach(v => {
    if (switched && isMap(v)) return;
    out.push([severityFor(v, false), "Stopped using " + v.vendor, v.category + "." + (after.has(key(v)) ? " Only the verification record is left." : "")]);
  });
  verifiedAdded.forEach(v => out.push([severityFor(v, true), "Verified the domain with " + v.vendor, v.category + ". " + seenIn(v)]));
  verifiedRemoved.forEach(v => out.push([severityFor(v, false), "Removed the domain record for " + v.vendor, v.category + "."]));

  const p = prev.posture, n = next.posture;
  if (p.dmarc !== n.dmarc) {
    if (POLICY_RANK[n.dmarc] > POLICY_RANK[p.dmarc]) out.push([POLICY_RANK[n.dmarc] >= 2 ? "critical" : "high", "DMARC tightened", "From " + p.dmarc + " to " + n.dmarc + ". Companies usually do this after a spoofing scare or before a big send."]);
    else out.push(["high", "DMARC rolled back", "From " + p.dmarc + " to " + n.dmarc + ". A rollback usually means real mail broke."]);
  } else if (p.pct !== n.pct) {
    out.push(["medium", "DMARC enforcement percentage changed", "From " + p.pct + "% to " + n.pct + "%."]);
  }
  if (p.spfLookups <= 10 && n.spfLookups > 10) out.push(["high", "SPF went over the lookup limit", "Now " + n.spfLookups + " lookups. Mail from some senders may start failing."]);
  else if (p.spfLookups > 10 && n.spfLookups <= 10) out.push(["medium", "SPF back under the limit", "Now " + n.spfLookups + " lookups."]);
  if (p.spfAll !== n.spfAll) out.push(["medium", "SPF ending changed", "From " + p.spfAll + " to " + n.spfAll + "."]);
  return out;
}
api.compare = compare;

// Two reads in a row have to agree before a change counts. Keeps only the rows
// that show up in both comparisons.
api.confirmed = function (first, second) {
  const seen = new Set(second.map(r => r[1] + "|" + r[2]));
  return first.filter(r => seen.has(r[1] + "|" + r[2]));
};

// The answered lookups from a read, small enough to publish next to the result.
api.rawAnswers = function (read) {
  return read.log.filter(e => e.answers.length).map(e => ({ name: e.name, type: e.type, answers: e.answers.map(x => x.data) }));
};

if (typeof module !== "undefined" && module.exports) module.exports = api;
else root.StackEngine = api;
})(typeof window !== "undefined" ? window : globalThis);
