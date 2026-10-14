// The synthetic access log the identity page and the log check try:
// documentation addresses (RFC 5737), a reserved host, and range files that
// stand in for the providers'. Never a provider's real file or a real
// request.

export const EXAMPLE_HOST = "host=www.example.org";
const UA = (token) => `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ${token}; +https://provider.example/bot)`;
const BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
const line = ([ip, t, path, ua]) => `${ip} - - [04/Oct/2026:${t} +0000] "GET ${path} HTTP/1.1" 200 512 "-" "${ua}"`;
const IDENTITY_LINES = [
  ["192.0.2.10", "08:10:00", "/pricing", UA("ChatGPT-User/1.0")],
  ["203.0.113.50", "08:10:04", "/admin/login", UA("ChatGPT-User/1.0")],
  ["198.51.100.5", "08:11:12", "/docs/", UA("Claude-User/1.0")],
  ["198.51.100.77", "08:11:30", "/docs/api", UA("Claude-User/1.0")],
  ["192.0.2.140", "08:12:02", "/", BROWSER],
  ["203.0.113.60", "08:12:40", "/.env", UA("PerplexityBot/1.0")],
  ["203.0.113.9", "08:13:05", "/search?q=opening+hours", UA("Google-Agent")],
  ["198.51.100.99", "08:14:00", "/", BROWSER],
];
export const EXAMPLE_LOG = IDENTITY_LINES.map(line).join("\n") + "\n";

// The log check's example adds a short probing run from one address that
// passes as a provider's agent: test payloads, a run tag and a request-bin
// callback on a reserved name.
export const PROBE_LOG = EXAMPLE_LOG + [
  ["203.0.113.50", "08:15:00", "/account?id=1'%20OR%201=1--&uqtag=exec4k", UA("ChatGPT-User/1.0")],
  ["203.0.113.50", "08:15:02", "/account?id=2'%20OR%201=1--&uqtag=exec4k", UA("ChatGPT-User/1.0")],
  ["203.0.113.50", "08:15:05", "/export?next=https://webhook.site/5e8d2c40-3333-4d1e-8f77-6a5b4c3d2e1f&uqtag=exec4k", UA("ChatGPT-User/1.0")],
  ["203.0.113.50", "08:15:09", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E&uqtag=exec4k", UA("ChatGPT-User/1.0")],
].map(line).join("\n") + "\n";

export const EXAMPLE_FILES = {
  ranges: {
    "openai.chatgpt-user": JSON.stringify({ creationTime: "2026-10-01T00:00:00", prefixes: [{ ipv4Prefix: "192.0.2.0/26" }] }),
    "anthropic.bots": JSON.stringify({ prefixes: [{ ipv4Prefix: "198.51.100.0/28" }] }),
    "perplexity.bot": JSON.stringify({ prefixes: [{ ipv4Prefix: "192.0.2.128/26" }] }),
  },
  directories: {},
};
