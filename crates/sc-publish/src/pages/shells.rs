//! The interactive pages' static markup. Their modules in `site/js/pages/`
//! fill them in; the markup carries no data, only controls and empty states.

/// The analysis workbench: input and summary, views, context, then report.
pub const ANALYZE: &str = r#"<header class="page-head compact"><h1>Workbench</h1>
<p class="lede">Paste or load records and the page grades, links and times them with the same rules as the CLI. It runs in this page via WebAssembly: nothing you paste is uploaded. Record text is shown as inert text, URLs defanged.</p></header>
<nav class="steps" aria-label="Workbench steps">
<button type="button" data-step="input" aria-current="step"><span>1</span> Input</button>
<button type="button" data-step="explore"><span>2</span> Explore</button>
<button type="button" data-step="context"><span>3</span> Context</button>
<button type="button" data-step="report"><span>4</span> Report</button>
</nav>
<div class="workbench">
<section class="pane pane-input" data-pane="input" aria-labelledby="h-input">
<h2 id="h-input">Records</h2>
<div id="input-box">
<div id="drop" class="dropzone">
<p class="drop-lead">Paste records below, drop a file here, or start from an example.</p>
<div class="row drop-actions"><button type="button" id="example" class="primary">Try an example</button><label class="file button">Load file<input type="file" id="file" accept=".ndjson,.jsonl,.json,.txt,.csv,.log"></label></div>
<label for="input" class="sr-only">Records</label>
<textarea id="input" class="mono" rows="8" spellcheck="false" placeholder='{"ts":"2026-10-04T08:10:00Z","url":"https://..."}' aria-describedby="input-hint"></textarea>
<p id="drop-status" class="hint" role="status" hidden></p>
</div>
<p class="hint" id="input-hint">NDJSON, a JSON array, Wayback CDX JSON, one URL per line (optionally after a timestamp), or a web server access log (name your host in the field map: <code>host=www.example.org</code>).</p>
<div class="row">
<label class="sr-only" for="format">Input format</label>
<select id="format"><option value="auto">auto-detect</option><option value="ndjson">NDJSON</option><option value="json">JSON</option><option value="lines">URL lines</option><option value="access_log">Access log</option></select>
<label class="sr-only" for="map">Field map</label><input id="map" class="grow mono" spellcheck="false" placeholder="field map, e.g. ts=submitted_at,url=page.url">
</div>
<div class="row"><button type="button" id="run" class="primary" disabled>Analyse</button></div>
</div>
<div id="input-collapsed" class="input-collapsed" hidden><span id="input-count"></span><button type="button" id="input-edit" aria-controls="input-box" aria-expanded="false">Edit</button></div>
<p class="hint" data-engine-status aria-live="polite"></p>
<p id="rules-note" class="hint" hidden></p>
<p id="example-note" class="hint note" hidden>Example loaded: the synthetic showcase the home page walks through. None of it was collected; target hosts are placeholders and networks documentation ASNs.</p>
<p id="preset-note" class="hint note" hidden>Access-log preset: paste your web server's log (Common or Combined Log Format) and put your own host in the field map, e.g. <code>host=www.example.org</code>. The log stays in this page.</p>
<div id="alert" class="alert" role="alert" hidden></div>
<p id="warnings" class="warn" role="status" hidden></p>
<div id="summary" hidden></div>
<h3 class="pane-sub" id="clusters-h">Clusters</h3>
<div id="cluster-list" class="cluster-list"><p class="hint">Analyse records to see their clusters: records linked by shared inbox IDs, unique tags, or the same target in a short window.</p></div>
</section>
<section class="pane pane-viz" data-pane="explore" aria-labelledby="h-viz">
<h2 id="h-viz">Explore</h2>
<div class="viz-tabs" role="tablist" aria-label="Views">
<button type="button" role="tab" id="tab-runs" aria-controls="viz-panel" aria-selected="true" data-view="runs">Runs</button>
<button type="button" role="tab" id="tab-fleet" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="fleet">Fleet</button>
<button type="button" role="tab" id="tab-swarm" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="swarm">Swarm</button>
<button type="button" role="tab" id="tab-heat" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="heat">Rules × clusters</button>
<button type="button" role="tab" id="tab-rhythm" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="rhythm">Rhythm</button>
<button type="button" role="tab" id="tab-strip" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="strip">Endpoints × time</button>
<button type="button" role="tab" id="tab-hourly" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="hourly">Hourly</button>
</div>
<div id="viz-panel" class="viz-panel" role="tabpanel" aria-labelledby="tab-runs" tabindex="0"><div class="empty-state"><p>Runs over time, the fleet and swarm graphs, rules against clusters and the hourly rhythm appear here once records are analysed.</p></div></div>
<div id="filter-bar" class="filter-bar" aria-live="polite"></div>
</section>
<aside class="pane pane-context" data-pane="context" aria-labelledby="h-ctx">
<h2 id="h-ctx">Context</h2>
<div id="context" aria-live="polite"><p class="hint">Select a cluster, a run, a graph node or a record to see its timing, hints and records here.</p></div>
<template id="tpl-fm15"><a href="../docs/manual/15-misalignment/#fm-153-scope-tests">SC-FM chapter 15</a></template>
<h3 class="pane-sub">Links between clusters</h3>
<p class="hint">Hints to check, not evidence: none changes a score or merges clusters.</p>
<div id="links"><p class="hint">None yet.</p></div>
</aside>
</div>
<section class="pane pane-tables" data-pane="explore" aria-labelledby="records-h">
<div class="sub-head"><h2 class="pane-sub" id="records-h">Flagged records</h2><button type="button" id="csv-records" class="small" disabled>Download CSV</button></div>
<div class="row table-tools">
<label>Sort by <select id="rec-sort"><option value="score">score</option><option value="time">time</option><option value="cluster">cluster</option></select></label>
<label class="grow">Filter <input id="rec-filter" type="search" class="mono" spellcheck="false" placeholder="text in the defanged URL, or a rule id" aria-describedby="rec-filter-hint"></label>
</div>
<p class="hint" id="rec-filter-hint">The filter matches the defanged URL and the rule ids, ignoring case. The CSV holds the records the table lists, in its order.</p>
<div id="records"><p class="hint">No records yet.</p></div>
<div class="sub-head"><h2 class="pane-sub" id="endpoints-h">Endpoints</h2><button type="button" id="csv-endpoints" class="small" disabled>Download CSV</button></div>
<p class="hint">Flagged requests per target host; times are UTC. Hits counts the suggestive or significant records to the host, out of every record that targets it (hits / all). "Ongoing" means hit within 7 days of the newest record loaded: what an affected operator checks their logs for.</p>
<div id="endpoints"><p class="hint">No endpoints yet.</p></div>
</section>
<section class="card pane-report" data-pane="report" aria-labelledby="h-report">
<h2 id="h-report">Report</h2>
<p class="hint">A disclosure draft from this analysis, scoped to the selected cluster if there is one. It follows the CLI's naming gate: outside case notes, a developer is named only on evidence at or above the level you pick. Model names in requests never name one on their own; an ASN names the host.</p>
<div class="row">
<label>Audience <select id="audience"><option value="internal">Internal case notes</option><option value="provider">AI provider</option><option value="affected">Affected operator</option><option value="indicator">Indicator notice (names no host)</option><option value="public">Naming update (names hosts)</option></select></label>
<label class="grow">Reporter <input id="reporter" placeholder="Name and contact"></label>
<label class="grow">Name a developer only on <select id="min-named" disabled><option value="">the default level (set when the engine loads)</option></select></label>
</div>
<details class="claims"><summary>Claims from case work <span id="claims-count" class="hint"></span></summary>
<p class="hint">The JSON array <code>swarmchase report --claims</code> reads, e.g. <code>[{"party":"Example AI","role":"developer","evidence":"provider_confirmed","details":["confirmed in writing"]}]</code>. Kept in this page only.</p>
<label for="claims" class="sr-only">Claims JSON</label><textarea id="claims" class="mono" rows="4" spellcheck="false"></textarea>
<p id="claims-status" class="warn" role="status" hidden></p></details>
<div class="row"><button type="button" id="draft-report" class="primary" disabled>Draft the report</button><button type="button" id="copy-report" disabled>Copy</button><button type="button" id="dl-report" disabled>Download .md</button><button type="button" id="dl-json" disabled>Download analysis .json</button></div>
<pre id="report" class="report" tabindex="0" aria-label="Report draft">Analyse records to draft a report.</pre>
</section>
<section class="card pane-report" data-pane="report" aria-labelledby="h-sightings">
<h2 id="h-sightings">Share sightings</h2>
<p class="hint">A swarm that hits many sites is invisible to any one of them. A sightings file lets you share what it left in your log without sharing the log: keyed hashes of its run tags, inbox ids and captured secrets, how its requests were made, the hours it was active and its grade. No URL, path, query value, IP address, user agent or cookie goes in, and your host names only if you tick the box. The page shows the whole file before you save it and sends nothing; you choose whether to send it, and to whom. See <a href="../operators/#share-sightings">sharing sightings</a>.</p>
<div class="row">
<label class="check"><input type="checkbox" id="sight-hosts"> Include my host names (defanged)</label>
<label class="grow">Describe yourself (optional) <input id="sight-operator" placeholder="e.g. the case id from our report" maxlength="120"></label>
</div>
<div class="row"><button type="button" id="sight-prepare" class="primary" disabled>Prepare sightings</button><button type="button" id="sight-dl" disabled>Download sightings .json</button></div>
<div id="sight-summary" aria-live="polite"></div>
<pre id="sight-preview" class="report" tabindex="0" aria-label="Sightings file to be saved">Analyse records, then press Prepare to see exactly what a sightings file would hold.</pre>
</section>"#;

pub const UNWRAP: &str = r#"<header class="page-head compact"><h1>Unwrap a URL</h1>
<p class="lede">See the relay and carrier layers inside one URL, its real target, and the rules each layer triggers. The URL is never opened; everything runs in this page.</p></header>
<section class="card">
<label for="unwrap-url">URL</label>
<div class="row"><input id="unwrap-url" class="grow mono" spellcheck="false" placeholder="https://r.jina.ai/https://..." aria-describedby="unwrap-hint"><button type="button" id="unwrap-run" class="primary" data-needs-engine disabled aria-busy="true">Unwrap</button><button type="button" id="unwrap-example" data-needs-engine disabled aria-busy="true">Try an example</button></div>
<p class="hint" id="unwrap-hint">The whole URL, with its scheme (<code>https://</code>). The example is a synthetic record from the showcase: a relay in front of a placeholder host, with a request bin as the callback.</p>
<p class="hint" data-engine-status aria-live="polite"></p><p id="rules-note" class="hint" hidden></p>
<div id="unwrap-out" aria-live="polite"></div>
</section>"#;

pub const TOOLS: &str = r#"<header class="page-head compact"><h1>Tools</h1>
<p class="lede">Small tools that run in this page: check an evidence bundle, read a <code>security.txt</code>, defang URLs. Each loads what it needs the first time you use it, and nothing you pick or paste leaves the page. Also: <a href="../unwrap/">unwrap a URL</a>, and <a href="../identity/">check the AI agents your log declares</a> against their providers' published ranges and keys.</p></header>
<section class="card" aria-labelledby="bundle-h">
<h2 id="bundle-h">Check an evidence bundle</h2>
<p class="lede-card">Got a report? Pick the files attached to the email.</p>
<p class="hint">Pick the files of a bundle from <code>swarmchase case bundle</code> (<code>records.ndjson</code>, <code>analysis.json</code>, <code>stamp.json</code>, <code>MANIFEST.sha256</code>, and <code>MANIFEST.sha256.sig</code> when it is signed) or its folder. The page checks the manifest's signature against the key this site publishes, each SHA-256 against the manifest, re-runs the analysis with the bundled rules (or your edited ones), and compares every tier and cluster with the stamp, as <code>swarmchase case verify</code> does. It then shows the method and evaluation the stamp cites, the attribution layers the records support (add a <code>claims.json</code> from case work to include its claims), the runs, any candidate fleets and escalations, and the records. The files are read in this page only.</p>
<div class="row">
<label class="file button primary">Pick files<input type="file" id="case-files" multiple accept=".ndjson,.json,.sha256"></label>
<label class="file button">Pick folder<input type="file" id="case-dir" webkitdirectory></label>
<button type="button" id="case-example">Load the showcase bundle</button>
<span id="case-picked" class="hint"></span></div>
<p class="hint">No bundle to hand? The showcase bundle is synthetic: built with this site from the showcase records the home page walks through. None of it was collected.</p>
<p class="hint card-status" data-tools-status aria-live="polite"></p>
<div id="case-out" aria-live="polite"></div>
</section>
<section class="card" aria-labelledby="sectxt-h">
<h2 id="sectxt-h">Read a security.txt</h2>
<p class="hint">Paste an organisation's <code>/.well-known/security.txt</code> to pull out who to notify. Or run <code>swarmchase contact &lt;domain&gt;</code>.</p>
<label for="sectxt" class="sr-only">security.txt</label><textarea id="sectxt" class="mono" rows="7" spellcheck="false" placeholder="Contact: mailto:security@example.org&#10;Expires: 2027-01-01T00:00:00Z"></textarea>
<div class="row"><button type="button" id="sectxt-run" class="primary" disabled>Parse</button><span class="hint" id="sectxt-wait">Paste a security.txt to parse it.</span></div>
<p class="hint card-status" data-tools-status aria-live="polite"></p>
<div id="sectxt-out"></div>
</section>
<section class="card" aria-labelledby="defang-h">
<h2 id="defang-h">Defang</h2>
<p class="hint" id="defang-hint">Make URLs safe to paste into reports and chat: <code>hxxps://example[.]org/</code>. Every <code>http</code> and <code>https</code> URL in the text changes, nested ones too: its scheme, and the dots of its host. Bare host names and IP addresses outside a URL are left as typed.</p>
<label for="defang-in" class="sr-only">Text to defang</label><textarea id="defang-in" class="mono" rows="4" spellcheck="false" aria-describedby="defang-hint"></textarea>
<p class="hint card-status" data-engine-status aria-live="polite"></p>
<div id="defang-result" hidden><h3 class="pane-sub" id="defang-out-h">Defanged</h3>
<pre id="defang-out" class="report" tabindex="0" aria-labelledby="defang-out-h" aria-live="polite"></pre>
<div class="row"><button type="button" id="defang-copy" class="small">Copy</button></div></div>
</section>"#;

/// Check my logs: an operator pastes its access log once and gets the
/// workbench's access-log analysis and the identity check on the same text,
/// then a plain summary and what to do next ([`site/js/pages/checklog.js`]).
/// The next steps are links in the markup; the script only shows them.
pub const CHECK_LOGS: &str = r##"<header class="page-head compact"><h1>Check my logs</h1>
<p class="lede">For a site operator: paste or drop your web server's access log once. The page runs the same rules as the workbench's access-log preset over the requests to your host, and checks every request that says it comes from an AI provider's agent against the ranges the provider publishes, then sums both up in plain words. It runs in this page: your log is never uploaded, and nothing is fetched from anyone.</p></header>
<section class="card" aria-labelledby="cl-log-h">
<h2 id="cl-log-h">1. Your log</h2>
<div id="cl-drop" class="dropzone">
<p class="drop-lead">Paste your log below, drop the file here, or try the synthetic example.</p>
<div class="row drop-actions"><label class="file button">Load file<input type="file" id="cl-file" accept=".log,.txt"></label><button type="button" id="cl-example">Try an example</button></div>
<label for="cl-input" class="sr-only">Access log</label>
<textarea id="cl-input" class="mono" rows="8" spellcheck="false" aria-describedby="cl-input-hint" placeholder='203.0.113.7 - - [04/Oct/2026:08:10:00 +0000] "GET /search?q=... HTTP/1.1" 200 512 "-" "Mozilla/5.0"'></textarea>
<p id="cl-drop-status" class="hint" role="status" hidden></p>
</div>
<p class="hint" id="cl-input-hint">Common or Combined Log Format (Combined carries the user agent the identity check reads). Behind a proxy, log the forwarded client address, not the proxy's.</p>
<div class="row"><label class="grow">Your host, as visitors type it <input id="cl-host" class="mono" spellcheck="false" placeholder="www.example.org" aria-describedby="cl-host-hint"></label></div>
<p class="hint" id="cl-host-hint">An access log does not name the site it belongs to; the analysis needs it to read each request as a URL.</p>
<div class="row"><button type="button" id="cl-run" class="primary" disabled>Check my log</button></div>
<p class="hint card-status" data-tools-status aria-live="polite"></p><p id="rules-note" class="hint" hidden></p>
<p id="cl-example-note" class="hint note" hidden>Example loaded: a synthetic log from documentation addresses on a reserved host, checked against synthetic range files that stand in for the providers' files. None of it was collected.</p>
<div id="cl-alert" class="alert" role="alert" hidden></div>
</section>
<section class="card" id="cl-result" aria-labelledby="cl-result-h" hidden>
<h2 id="cl-result-h" tabindex="-1">2. What the page found</h2>
<div id="cl-summary" aria-live="polite"></div>
</section>
<section class="card" id="cl-next" aria-labelledby="cl-next-h" hidden>
<h2 id="cl-next-h">3. What to do next</h2>
<ul class="next-steps">
<li><strong>Look closer.</strong> The <a href="../analyze/#preset=access-log">workbench's access-log preset</a> shows the same analysis with its clusters, runs and timing; the <a href="../identity/">agent identity page</a> lists every declared agent and takes newer copies of the providers' files. The workbench link carries the log you checked over within this browser tab, never in the address; on the identity page, paste it again.</li>
<li><strong>Share sightings.</strong> From the workbench, a <a href="../operators/#share-sightings">sightings file</a> lets the same swarm be matched across sites without sending your log.</li>
<li><strong>Report a swarm.</strong> If the requests look like an AI agent acting against your site, <a href="../submit/">report it</a>: the form builds the report in your browser and sends nothing itself.</li>
<li><strong>Talk to us privately.</strong> Questions, or a report from us to answer: <a href="../contact/">contact</a>. Please do not open a public issue that names your host.</li>
</ul>
<p class="hint">Flagged requests and spoofed agents are hints to check against the rest of your logs, not proof of who sent them (<a href="../operators/#what-to-expect-in-your-own-logs">what to expect in your own logs</a>).</p>
</section>"##;

/// Shown on the identity page when the build embedded no provider's files.
/// The page script hides it while the operator's own copies or the example
/// are in use.
pub const NO_PROVIDER_FILES_IDENTITY: &str = r##"<div id="no-provider-files" class="alert" role="note"><p><strong>Spoofing cannot be checked with this site's files.</strong></p><p>This site was built without the providers' published address ranges and signing keys, so a request that names an AI provider's agent stays a claim: nothing is verified and nothing is shown spoofed. Load copies of the providers' files under Providers' files to check against them.</p></div>"##;

/// Shown on Check my logs when the build embedded no provider's files.
pub const NO_PROVIDER_FILES_CHECK_LOGS: &str = r##"<div id="no-provider-files" class="alert" role="note"><p><strong>Spoofing cannot be checked with this site's files.</strong></p><p>This site was built without the providers' published address ranges and signing keys, so a request that names an AI provider's agent stays a claim: nothing is verified and nothing is shown spoofed. The rules still run. The <a href="../identity/">agent identity page</a> takes copies of the providers' files you load.</p></div>"##;

/// Agent identity: an operator checks the agents its own log declares
/// against the providers' published ranges and keys
/// ([`site/js/pages/identity.js`]). The page fetches nothing.
pub const IDENTITY: &str = r##"<header class="page-head compact"><h1>Agent identity</h1>
<p class="lede">Which requests in your log say they come from an AI provider's agent (<code>ChatGPT-User</code>, <code>Claude-User</code>, <code>Perplexity-User</code>, <code>Google-Agent</code> and others), and whether the address ranges and signing keys the provider publishes bear that out. It runs in this page: your log is never uploaded, and the page fetches nothing from the providers. Method: <a href="../docs/reference/identity/">declared agent identity</a>.</p></header>
<section class="card" aria-labelledby="id-log-h">
<h2 id="id-log-h">Your log</h2>
<label for="id-input" class="sr-only">Log</label>
<textarea id="id-input" class="mono" rows="8" spellcheck="false" aria-describedby="id-input-hint" placeholder='203.0.113.7 - - [04/Oct/2026:08:10:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; ChatGPT-User/1.0)"'></textarea>
<p class="hint" id="id-input-hint">A web server access log (Combined Log Format, so the user agent is there), or NDJSON with <code>ip</code>, <code>user_agent</code> and, for signatures, the request <code>headers</code>. Behind a proxy, log the forwarded client address, not the proxy's.</p>
<div class="row">
<label class="file button">Load file<input type="file" id="id-file" accept=".log,.txt,.ndjson,.jsonl,.json"></label>
<label class="sr-only" for="id-format">Input format</label>
<select id="id-format"><option value="auto">auto-detect</option><option value="access_log">Access log</option><option value="ndjson">NDJSON</option><option value="json">JSON</option></select>
<label class="sr-only" for="id-map">Field map</label><input id="id-map" class="grow mono" spellcheck="false" placeholder="field map, e.g. host=www.example.org">
</div>
<div class="row"><button type="button" id="id-run" class="primary">Check</button><button type="button" id="id-example">Try an example</button></div>
<p class="hint card-status" data-tools-status aria-live="polite"></p>
<p id="id-example-note" class="hint note" hidden>Example loaded: a synthetic log from documentation addresses, checked against synthetic range files that stand in for the providers' files. None of it is a provider's real file or a real request.</p>
<div id="id-alert" class="alert" role="alert" hidden></div>
</section>
<section class="card" aria-labelledby="id-files-h">
<h2 id="id-files-h">Providers' files</h2>
<p class="hint">Without the ranges and keys a provider publishes, a user agent is only a claim: anyone can write one, and nothing can be verified or shown spoofed. This page never fetches those files itself: a request from your browser to a provider would tell it who is checking, and the site allows requests to its own files only. It starts with the copies this site was built with, if any, dated below. To check against newer files, download them from the addresses listed (or take the files <code>swarmchase identity refresh</code> writes into <code>&lt;data&gt;/identity/</code>) and load them here; they stay in this page.</p>
<p id="id-snapshot" class="hint" aria-live="polite"></p>
<div class="row"><label class="file button">Load files<input type="file" id="id-files" multiple accept=".json,.txt"></label><button type="button" id="id-reset" disabled>Forget loaded files</button></div>
<p id="id-files-status" class="hint" role="status" hidden></p>
<div id="id-file-table"></div>
</section>
<section class="card" aria-labelledby="id-out-h">
<h2 id="id-out-h">Result</h2>
<div id="id-out" aria-live="polite"><p class="hint">Check a log to see each record's class here.</p></div>
</section>"##;

/// Report a swarm: a form that builds an SC-Submission v1 document in the
/// page ([`site/js/pages/submit.js`]). The page sends nothing.
pub const SUBMIT: &str = r##"<header class="page-head compact"><h1>Report a swarm</h1>
<p class="lede">Saw AI agents probing, scraping or coordinating against others? Describe it here and the page builds an <a href="../docs/specs/submission-v1/">SC-Submission v1</a> document you send us privately. Agents may write the document directly from the spec and its <a href="../schemas/sc-submission-v1.json">schema</a>. This page sends nothing: everything stays in your browser until you send the file yourself.</p></header>
<section class="card" aria-labelledby="sub-who-h">
<h2 id="sub-who-h">Who is reporting</h2>
<p class="hint">Kept private and never published. A report may be anonymous.</p>
<div class="row">
<label>Are you an AI agent? <select id="sub-agent"><option value="false">No, a person or organisation</option><option value="true">Yes, an AI agent</option></select></label>
<label>Role <select id="sub-role"><option value="">(not given)</option><option value="operator">Operator of an affected system</option><option value="researcher">Researcher</option><option value="provider">AI provider</option><option value="bystander">Bystander</option><option value="other">Other</option></select></label>
</div>
<div class="row">
<label class="grow">Name (optional) <input id="sub-name" spellcheck="false"></label>
<label class="grow">Contact (optional) <input id="sub-contact" spellcheck="false" placeholder="an email address or handle"></label>
</div>
<div class="row" id="sub-agent-row" hidden>
<label class="grow">Deployed by <input id="sub-operator" spellcheck="false"></label>
<label class="grow">Model <input id="sub-model" spellcheck="false"></label>
</div>
</section>
<section class="card" aria-labelledby="sub-claim-h">
<h2 id="sub-claim-h">What you saw</h2>
<label for="sub-summary">Summary</label>
<textarea id="sub-summary" rows="4" spellcheck="true"></textarea>
<div class="row">
<label>Kind <select id="sub-kind"><option value="unknown">Not sure</option><option value="run">One agent run</option><option value="fleet">Several runs by one operator</option><option value="swarm">Several agents interacting</option></select></label>
<label>First seen <input id="sub-first" type="datetime-local" aria-describedby="sub-time-note"></label>
<label>Last seen <input id="sub-last" type="datetime-local" aria-describedby="sub-time-note"></label>
<label>Times are in <select id="sub-tz" aria-describedby="sub-time-note"><option value="local">my local time</option><option value="utc">UTC</option></select></label>
<label>Number of agents (estimate) <input id="sub-agents" type="number" min="1" step="1"></label>
</div>
<p class="hint" id="sub-time-note">The report stores times in UTC. Local times are converted with this browser's time zone.</p>
<div class="row"><label class="grow">Target hosts <input id="sub-targets" spellcheck="false" placeholder="www.example.org, api.example.org"></label></div>
</section>
<section class="card" aria-labelledby="sub-ev-h">
<h2 id="sub-ev-h">Evidence</h2>
<p class="hint">What would be hard to fabricate counts most: records in public sources (scan services, web archives, GH Archive, package registries, certificate logs) dated well before you report, and signed requests or signed exports. Your own logs help, but only you can check them; bare values help least. We never open a URL you give, and never contact a callback inbox you name: we look records up by their id.</p>
<div class="row">
<label>Add <select id="ev-type"><option value="public_record">A public record</option><option value="log_lines">Log lines</option><option value="signed">A signed artifact</option><option value="indicator">An indicator value</option></select></label>
<button type="button" id="ev-add">Add evidence</button>
</div>
<div id="ev-list"></div>
</section>
<section class="card" aria-labelledby="sub-out-h">
<h2 id="sub-out-h">Your report</h2>
<div id="sub-problems" class="alert" role="status" hidden></div>
<div class="row"><button type="button" id="sub-copy" class="primary">Copy JSON</button><button type="button" id="sub-dl">Download .json</button></div>
<pre id="sub-json" class="report" tabindex="0" aria-label="Submission JSON"></pre>
<h3>Send it</h3>
<p>Open a <a href="https://github.com/AndrewAltimit/swarmchasing/security/advisories/new">GitHub private vulnerability report</a> on this repository and paste the JSON into it, or attach the file. If we sent you a report, you may reply to it with the file attached instead. Please do not open a public issue: it would publish the hosts before anyone checked them.</p>
<h3>What happens to it</h3>
<p class="hint">Every report is treated as untrusted. We check the records you cite by their ids, compare them with what our own watch already holds, and look closer only when the evidence would have been hard to fabricate. Nothing you send is published. If we open a case, it rests on records we verified ourselves and goes through the usual review; you are not named unless you ask to be. See the <a href="../docs/reference/inbox/">inbox reference</a> and the <a href="../docs/policies/#outside-submissions">policy</a>.</p>
</section>"##;

/// Shown above the operators' guide: the access-log check, then how to tell
/// a report is ours, when a name becomes public, and how to reach the
/// project without naming a host in public.
pub const OPERATORS_PANEL: &str = r##"<aside class="card callout-card" aria-labelledby="check-h">
<h2 id="check-h">Check your access log in the browser</h2>
<p><a href="../check-logs/">Check my logs</a> takes your web server's log (Common or Combined Log Format) once, runs the indicator rules over the requests to your host and checks every agent that names itself against its provider's published addresses, then says in plain words what it found and what to do next. The workbench's access-log preset shows the same analysis in full. The log stays in the page and is never uploaded.</p>
<p><a class="button primary" href="../check-logs/">Check my logs</a> <a class="button" href="../analyze/#preset=access-log">Open the access-log preset</a></p>
<p>Requests that name an AI provider's agent (<code>ChatGPT-User</code>, <code>Claude-User</code>, a signature) can be checked against the ranges and keys the provider publishes, in the browser too: <a href="../identity/">agent identity</a> (<a href="#agents-that-name-themselves">how</a>).</p>
</aside>
<aside class="card callout-card" aria-labelledby="contact-h">
<h2 id="contact-h">Received a report? Check it, and reach us privately</h2>
<p>A report cites a case id and carries an evidence bundle whose <code>stamp.json</code> names the same case. Check the bundle on the <a href="../tools/">tools page</a>: it re-runs the analysis in your browser and says whether the report follows from the records (<a href="#verify-an-evidence-bundle">what that shows</a>).</p>
<p>The indicator notice names and locates no affected organisation. Yours is named in a later update, 3 working days after your report (10 if your systems were compromised), or sooner only with your consent.</p>
<p>Reply to the report's address with the case id in the subject. No report? Use <a href="https://github.com/AndrewAltimit/swarmchasing/security/advisories/new">GitHub private vulnerability reporting</a> on this repository. Please do not open a public issue about an affected host: it would publish the name before its naming update.</p>
</aside>"##;

/// Shown above the providers' guide: the bundle check, the indicator clock,
/// and the reply channel.
pub const PROVIDERS_PANEL: &str = r##"<aside class="card callout-card" aria-labelledby="provider-check-h">
<h2 id="provider-check-h">Received a report? Check its bundle, then reply</h2>
<p>The report carries an evidence bundle. The tools page re-runs the analysis in your browser and says whether the report follows from the records; nothing is uploaded (<a href="#check-the-evidence">what that shows</a>).</p>
<p><a class="button primary" href="../tools/">Check a bundle</a></p>
<p>The indicator notice gives a provider no lead time of its own: it may be published as soon as every party has its report and every operator's indicator clock has run (no wait for most, 24 hours for a compromised operator). It is not an embargo: nothing a recipient says moves it (<a href="#when-the-notice-is-published">when the notice is published</a>).</p>
<p>Reply to the report's address with the case id in the subject. No report? Use <a href="https://github.com/AndrewAltimit/swarmchasing/security/advisories/new">GitHub private vulnerability reporting</a> on this repository.</p>
</aside>"##;

/// The 404 page: a notice link may arrive before its notice is published,
/// since reports go first. Links are added by the build (they need the
/// site's root path).
pub const NOT_FOUND: &str = r#"<header class="page-head"><h1>Page not found</h1>
<p class="lede">Nothing is published at this address. If a report pointed you to a notice here, it may not be published yet: reports go first, the indicator notice follows on a fixed clock, and affected organisations are named later. Notices keep their address once published; a retracted notice stays at its address with the retraction shown.</p></header>"#;

/// Contact, for every audience: the private channel, and which reply goes
/// where. Linked from every page's footer.
pub const CONTACT: &str = r##"<header class="page-head"><h1>Contact</h1>
<p class="lede">One private channel reaches the maintainers, whoever you are: <a href="https://github.com/AndrewAltimit/swarmchasing/security/advisories/new">GitHub private vulnerability reporting</a> on this repository. Only the maintainers can read what you send. Give a case or notice id if you have one, and say how to reach you.</p>
<p class="warn">Please do not open a public issue or discussion about an affected host or organisation. Anything posted there is public at once: it would name a party before its naming update, or show what a notice withholds.</p></header>
<ul class="audience">
<li><h2>You received a report about your site</h2><p>Reply to the address it came from, with the case id in the subject: questions, logs, statements, corrections and consent to earlier naming all go there. Found your organisation in a notice without a report? Use the private channel above and we will send you the full report.</p><p><a href="../operators/#contact">For operators</a></p></li>
<li><h2>You handle reports at an AI provider</h2><p>Reply to the report's address with the case id in the subject. If it reached the wrong team, tell us the right channel. No report? Use the private channel above.</p><p><a href="../providers/#reply-confirm-or-send-a-statement">For providers</a></p></li>
<li><h2>You saw a swarm, or you are an AI agent</h2><p>The submission page builds a structured report in your browser; send it through the private channel above. Agents can write it from the spec directly.</p><p><a href="../submit/">Report a swarm</a> · <a href="../llms.txt">llms.txt</a></p></li>
<li><h2>A problem with the toolkit or this site</h2><p>A security problem in the code or the site goes through the private channel above too. Bugs, rules and method questions that name no affected party belong in the repository's public issues.</p><p><a href="https://github.com/AndrewAltimit/swarmchasing/issues">Public issues</a> · <a href="../.well-known/security.txt">security.txt</a></p></li>
</ul>"##;
