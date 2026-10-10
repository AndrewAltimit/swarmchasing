//! The interactive pages' static markup. Their modules in `site/js/pages/`
//! fill them in; the markup carries no data, only controls and empty states.

/// The analysis workbench: input and summary, views, context, then report.
pub const ANALYZE: &str = r#"<header class="page-head compact"><h1>Analyze</h1>
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
<label for="input" class="sr-only">Records</label>
<textarea id="input" rows="9" spellcheck="false" placeholder='{"ts":"2026-10-04T08:10:00Z","url":"https://..."}' aria-describedby="input-hint"></textarea>
<p class="hint" id="input-hint">NDJSON, a JSON array, Wayback CDX JSON, one URL per line (optionally after a timestamp), or a web server access log (name your host in the field map: <code>host=www.example.org</code>).</p>
<div class="row">
<label class="file button">Load file<input type="file" id="file" accept=".ndjson,.jsonl,.json,.txt,.csv,.log"></label>
<label class="sr-only" for="format">Input format</label>
<select id="format"><option value="auto">auto-detect</option><option value="ndjson">NDJSON</option><option value="json">JSON</option><option value="lines">URL lines</option><option value="access_log">Access log</option></select>
</div>
<div class="row"><label class="sr-only" for="map">Field map</label><input id="map" class="grow" spellcheck="false" placeholder="field map, e.g. ts=submitted_at,url=page.url"></div>
<div class="row"><button type="button" id="run" class="primary" data-needs-engine disabled>Analyze</button><button type="button" id="example" data-needs-engine disabled>Try an example</button></div>
<p class="hint" data-engine-status aria-live="polite"></p>
<p id="rules-note" class="hint" hidden></p>
<p id="example-note" class="hint note" hidden>Example loaded: synthetic records written to exercise the rules. None were collected, the hosts are placeholders, and the labels are removed.</p>
<p id="preset-note" class="hint note" hidden>Access-log preset: paste your web server's log (Common or Combined Log Format) and put your own host in the field map, e.g. <code>host=www.example.org</code>. The log stays in this page.</p>
<p id="warnings" class="hint warn" role="status" hidden></p>
<div id="summary" hidden></div>
<h3 class="pane-sub" id="clusters-h">Clusters</h3>
<div id="cluster-list" class="cluster-list"><p class="hint">Analyse records to see their clusters: records linked by shared inbox IDs, unique tags, or the same target in a short window.</p></div>
</section>
<section class="pane pane-viz" data-pane="explore" aria-labelledby="h-viz">
<h2 id="h-viz">Explore</h2>
<div class="viz-tabs" role="tablist" aria-label="Views">
<button type="button" role="tab" id="tab-runs" aria-controls="viz-panel" aria-selected="true" data-view="runs">Runs</button>
<button type="button" role="tab" id="tab-fleet" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="fleet">Fleet</button>
<button type="button" role="tab" id="tab-heat" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="heat">Rules × clusters</button>
<button type="button" role="tab" id="tab-rhythm" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="rhythm">Rhythm</button>
<button type="button" role="tab" id="tab-strip" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="strip">Endpoints × time</button>
<button type="button" role="tab" id="tab-hourly" aria-controls="viz-panel" aria-selected="false" tabindex="-1" data-view="hourly">Hourly</button>
</div>
<div id="viz-panel" class="viz-panel" role="tabpanel" aria-labelledby="tab-runs" tabindex="0"><p class="hint empty-state">Views appear here after an analysis.</p></div>
<div id="filter-bar" class="filter-bar" aria-live="polite"></div>
<h3 class="pane-sub" id="records-h">Flagged records</h3>
<div id="records"><p class="hint">No records yet.</p></div>
<h3 class="pane-sub">Endpoints</h3>
<p class="hint">Flagged requests per target host. "Ongoing" means hit within 7 days of the newest record loaded: what an affected operator checks their logs for.</p>
<div id="endpoints"><p class="hint">No endpoints yet.</p></div>
</section>
<aside class="pane pane-context" data-pane="context" aria-labelledby="h-ctx">
<h2 id="h-ctx">Context</h2>
<div id="context" aria-live="polite"><p class="hint">Select a cluster, a run, a graph node or a record to see its timing, hints and records here.</p></div>
<h3 class="pane-sub">Links between clusters</h3>
<p class="hint">Hints to check, not evidence: none changes a score or merges clusters.</p>
<div id="links"><p class="hint">None yet.</p></div>
</aside>
</div>
<section class="card pane-report" data-pane="report" aria-labelledby="h-report">
<h2 id="h-report">Report</h2>
<p class="hint">A disclosure draft from this analysis, scoped to the selected cluster if there is one. It follows the CLI's naming gate: outside case notes, a developer is named only on evidence at or above the level you pick. Model names in requests never name one on their own; an ASN names the host.</p>
<div class="row">
<label>Audience <select id="audience"><option value="internal">Internal case notes</option><option value="provider">AI provider</option><option value="affected">Affected operator</option><option value="public">Public notice</option></select></label>
<label class="grow">Reporter <input id="reporter" placeholder="Name and contact"></label>
<label class="grow">Name a developer only on <select id="min-named"></select></label>
</div>
<details class="claims"><summary>Claims from case work <span id="claims-count" class="hint"></span></summary>
<p class="hint">The JSON array <code>swarmchase report --claims</code> reads, e.g. <code>[{"party":"Example AI","role":"developer","evidence":"provider_confirmed","details":["confirmed in writing"]}]</code>. Kept in this page only.</p>
<label for="claims" class="sr-only">Claims JSON</label><textarea id="claims" rows="4" spellcheck="false"></textarea>
<p id="claims-status" class="hint warn" role="status" hidden></p></details>
<div class="row"><button type="button" id="copy-report" disabled>Copy</button><button type="button" id="dl-report" disabled>Download .md</button><button type="button" id="dl-json" disabled>Download analysis .json</button></div>
<pre id="report" class="report" tabindex="0" aria-label="Report draft">Analyse records to draft a report.</pre>
</section>"#;

pub const UNWRAP: &str = r#"<header class="page-head compact"><h1>Unwrap a URL</h1>
<p class="lede">See the relay and carrier layers inside one URL, its real target, and the rules each layer triggers. The URL is never opened; everything runs in this page.</p></header>
<section class="card">
<label for="unwrap-url">URL</label>
<div class="row"><input id="unwrap-url" class="grow" spellcheck="false" placeholder="https://r.jina.ai/https://..."><button type="button" id="unwrap-run" class="primary" data-needs-engine disabled>Unwrap</button></div>
<p class="hint" data-engine-status aria-live="polite"></p><p id="rules-note" class="hint" hidden></p>
<div id="unwrap-out" aria-live="polite"></div>
</section>"#;

pub const TOOLS: &str = r#"<header class="page-head compact"><h1>Tools</h1>
<p class="lede">Small tools that run in this page: check an evidence bundle, read a <code>security.txt</code>, defang URLs. Also: <a href="../unwrap/">unwrap a URL</a>.</p>
<p class="hint" data-engine-status aria-live="polite"></p></header>
<section class="card" aria-labelledby="bundle-h">
<h2 id="bundle-h">Check an evidence bundle</h2>
<p class="hint">Pick the files of a bundle from <code>swarmchase case bundle</code> (<code>records.ndjson</code>, <code>analysis.json</code>, <code>stamp.json</code>, <code>MANIFEST.sha256</code>) or its folder. The page checks each SHA-256 against the manifest, re-runs the analysis with the bundled rules (or your edited ones), and compares every tier and cluster with the stamp, as <code>swarmchase case verify</code> does. The files are read in this page only.</p>
<div class="row">
<label class="file button">Pick files<input type="file" id="case-files" multiple accept=".ndjson,.json,.sha256" data-needs-engine disabled></label>
<label class="file button">Pick folder<input type="file" id="case-dir" webkitdirectory data-needs-engine disabled></label>
<span id="case-picked" class="hint"></span></div>
<div id="case-out" aria-live="polite"></div>
</section>
<section class="card" aria-labelledby="sectxt-h">
<h2 id="sectxt-h">Read a security.txt</h2>
<p class="hint">Paste an organisation's <code>/.well-known/security.txt</code> to pull out who to notify. Or run <code>swarmchase contact &lt;domain&gt;</code>.</p>
<label for="sectxt" class="sr-only">security.txt</label><textarea id="sectxt" rows="7" spellcheck="false"></textarea>
<div class="row"><button type="button" id="sectxt-run" class="primary" data-needs-engine disabled>Parse</button></div>
<div id="sectxt-out"></div>
</section>
<section class="card" aria-labelledby="defang-h">
<h2 id="defang-h">Defang</h2>
<p class="hint">Make URLs safe to paste into reports and chat: <code>hxxps://example[.]org/</code>.</p>
<label for="defang-in" class="sr-only">Text to defang</label><textarea id="defang-in" rows="4" spellcheck="false" data-needs-engine disabled></textarea>
<pre id="defang-out" class="report" aria-live="polite"></pre>
</section>"#;

/// Shown above the operators' guide.
pub const OPERATORS_PANEL: &str = r#"<aside class="card callout-card" aria-labelledby="check-h">
<h2 id="check-h">Check your access log in the browser</h2>
<p>The workbench has an access-log preset: paste your web server's log (Common or Combined Log Format), name your host in the field map, and it runs the same rules over your requests. The log is analysed in the page and never uploaded.</p>
<p><a class="button primary" href="../analyze/#preset=access-log">Open the access-log preset</a></p>
</aside>"#;

pub const NOT_FOUND: &str = r#"<header class="page-head"><h1>Page not found</h1>
<p class="lede">Nothing is published at this address. Notices keep their address once published; a retracted notice stays at its address with the retraction shown.</p></header>"#;
