# References

[Manual index](README.md) · Previous: [Glossary](glossary.md)

Every source the manual cites, grouped by use. Where a standard is paywalled, the link is its catalogue page.

## Standards and guidance

| Source | Cited for |
|---|---|
| Office of the Director of National Intelligence, *Intelligence Community Directive 203: Analytic Standards*, signed 2 January 2015, as amended. <https://archive.dni.gov/files/documents/ICD/ICD-203.pdf> | The likelihood table, the rule against combining confidence and likelihood in one sentence, and separating information from judgment ([chapter 8](08-confidence.md), [FM-7.6](07-attribution.md#fm-76-claim-tags), [FM-9.12](09-evaluation.md#fm-912-calibrated-public-language)). |
| S. Bradner, *Key words for use in RFCs to Indicate Requirement Levels*, RFC 2119, 1997. <https://www.rfc-editor.org/rfc/rfc2119> | Requirement words ([index](README.md#requirement-words)). |
| B. Leiba, *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*, RFC 8174, 2017. <https://www.rfc-editor.org/rfc/rfc8174> | Requirement words. |
| Regulation (EU) 2024/1689 (the AI Act), Article 73, *Reporting of serious incidents*. <https://eur-lex.europa.eu/eli/reg/2024/1689/oj> | Providers' reporting deadlines ([FM-12.5](12-interoperability.md#fm-125-regulatory-incident-reports)). |

## Disclosure

| Source | Cited for |
|---|---|
| ISO/IEC 29147:2018, *Information technology — Security techniques — Vulnerability disclosure*. <https://www.iso.org/standard/72311.html> | [FM-10.3](10-disclosure.md#fm-103-relation-to-vulnerability-disclosure-standards). |
| ISO/IEC 30111:2019, *Information technology — Security techniques — Vulnerability handling processes*. <https://www.iso.org/standard/69725.html> | [FM-10.3](10-disclosure.md#fm-103-relation-to-vulnerability-disclosure-standards). |
| ISO/IEC TR 5895:2022, *Cybersecurity — Multi-party coordinated vulnerability disclosure and handling*. <https://www.iso.org/standard/81807.html> | [FM-10.3](10-disclosure.md#fm-103-relation-to-vulnerability-disclosure-standards). |
| FIRST, *Guidelines and Practices for Multi-Party Vulnerability Coordination and Disclosure*, version 1.1, 2020. <https://www.first.org/global/sigs/vulnerability-coordination/multiparty/guidelines-v1.1> | Embargo defaults and the active-exploitation exception ([FM-10.3](10-disclosure.md#fm-103-relation-to-vulnerability-disclosure-standards)). |
| Coalition for Secure AI (CoSAI), *AI Incident Response Framework*, version 1.0, October 2025. <https://www.coalitionforsecureai.org/defending-ai-systems-a-new-framework-for-incident-response-in-the-age-of-intelligent-technology/> | Incident response for defenders of AI systems ([FM-16.5](16-other-methods.md#fm-165-standards-work-on-agents)). |
| FIRST, member team directory. <https://www.first.org/members/teams/> | Finding a national CSIRT ([FM-10.1](10-disclosure.md#fm-101-parties)). |
| E. Foudil, Y. Shafranovich, *A File Format to Aid in Security Vulnerability Disclosure*, RFC 9116, 2022. <https://www.rfc-editor.org/rfc/rfc9116> | security.txt contacts ([FM-10.4](10-disclosure.md#fm-104-contacts-and-channels)). |

## Threat frameworks

| Source | Cited for |
|---|---|
| MITRE, *ATLAS: Adversarial Threat Landscape for AI Systems*, data version 2026.09. <https://atlas.mitre.org/>; data: <https://github.com/mitre-atlas/atlas-data> | ATLAS technique ids and names ([FM-4.6](04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck)); agent communication and orchestration ([FM-1.3](01-scope.md#fm-13-groupings)); agent techniques in the crosswalk ([FM-12.4](12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks)). |
| OWASP GenAI Security Project, *OWASP Top 10 for Agentic Applications for 2026*, December 2025. <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/> | ASI01 to ASI10 in the crosswalk ([FM-12.4](12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks)). |
| MITRE, *ATT&CK Enterprise*. <https://attack.mitre.org/> | ATT&CK technique ids and names ([FM-4.6](04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck)). |

## Attribution practice

| Source | Cited for |
|---|---|
| K. Vanderlee, *DebUNCing Attribution: How Mandiant Tracks Uncategorized Threat Actors*, Mandiant, 17 December 2020. <https://cloud.google.com/blog/topics/threat-intelligence/how-mandiant-tracks-uncategorized-threat-actors> | Clusters that grow, merge and split before they are named ([FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split), [FM-5.13](05-linking.md#fm-513-cluster-lifecycle-and-identifiers)). |
| R. J. Heuer Jr., *Psychology of Intelligence Analysis*, CIA Center for the Study of Intelligence, 1999, chapter 8, "Analysis of Competing Hypotheses". <https://www.cia.gov/resources/csi/static/Pyschology-of-Intelligence-Analysis.pdf> | The competing-hypotheses worksheets ([FM-7.12](07-attribution.md#fm-712-competing-hypotheses)). |
| S. Caltagirone, A. Pendergast, C. Betz, *The Diamond Model of Intrusion Analysis*, technical report, 2013. <https://apps.dtic.mil/sti/pdfs/ADA586960.pdf> | Adversary, capability, infrastructure and victim against the attribution layers ([FM-16.3](16-other-methods.md#fm-163-analytic-and-coordination-frameworks)). |

## Incident reports

| Source | Cited for |
|---|---|
| J. Cable et al., *Early rogue AI agent activity and attempts to hack found on urlquery.net*, Transluce, 23 September 2026, and its labelled data release. <https://transluce.org/agent-activity> | Tier names ([FM-1.5](01-scope.md#fm-15-evidence-tiers)); the held-out labels ([FM-9.3](09-evaluation.md#fm-93-frozen-held-out-split)); a case study ([FM-13.4](13-case-study.md#fm-134-case-study-urlquerynet-agent-activity)); its grades, attribution wording and disclosure ([FM-16.1](16-other-methods.md#fm-161-published-incident-investigations)). |
| J. Cable et al., *AI Agents Targeted U.S. and Canadian Government Websites*, Transluce, 30 September 2026. <https://transluce.org/us-canada-gov> | Request patterns reconstructed in the regression set ([FM-9.2](09-evaluation.md#fm-92-regression-set)); a case study ([FM-13.5](13-case-study.md#fm-135-case-study-us-and-canadian-government-targets)); its sources and triage ([FM-16.1](16-other-methods.md#fm-161-published-incident-investigations)). |
| A. I. Perez, E. Elasky, R. Howard-Jones et al. (the Swarmchasers), *We found a Chinese agent fleet*, swarmcha.se, preliminary report dated 4 October 2026, with its dated changelog. <https://swarmcha.se/posts/chinese-agent-fleet> | The fleet and swarm distinction ([FM-1.3](01-scope.md#fm-13-groupings)); a withdrawn model-family exclusion ([FM-7.5](07-attribution.md#fm-75-model-family-layer)); a case study ([FM-13.6](13-case-study.md#fm-136-case-study-an-agent-fleet-reading-a-map-service)); a finding of no coordination ([FM-16.1](16-other-methods.md#fm-161-published-incident-investigations)). |
| R. Howard-Jones, *OpenAI agents tried to bruteforce a UN website's API fields*, swarmcha.se, 26 September 2026. <https://swarmcha.se/posts/openai-unctad> | Proxy use of a scan service, relays, echo-service answers, double encoding and attribution by shared addresses ([FM-16.1](16-other-methods.md#fm-161-published-incident-investigations)). |
| OpenAI, *Disrupting malicious uses of AI*, threat report series. <https://openai.com/index/disrupting-malicious-ai-uses> | Provider threat reports ([FM-16.2](16-other-methods.md#fm-162-provider-threat-reports)). |
| Anthropic, *Disrupting the first reported AI-orchestrated cyber espionage campaign*, 13 November 2025. <https://www.anthropic.com/news/disrupting-AI-espionage> | Provider threat reports ([FM-16.2](16-other-methods.md#fm-162-provider-threat-reports)). |

## Agent identity

| Source | Cited for |
|---|---|
| T. Meunier, S. Major, *HTTP Message Signatures for automated traffic*, Internet-Draft draft-ietf-webbotauth-httpsig-protocol, IETF Web Bot Auth working group, work in progress. <https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/> | Signed agent requests and the `Signature-Agent` header ([FM-7.11](07-attribution.md#fm-711-declared-agent-identity)). |
| *Registry and Signature Agent card for Web bot auth*, Internet-Draft draft-meunier-webbotauth-registry, work in progress. <https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/> | Signature agent cards ([FM-7.11](07-attribution.md#fm-711-declared-agent-identity)). |
| NIST, *Announcing the "AI Agent Standards Initiative" for Interoperable and Secure Innovation*, 17 February 2026. <https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure> | Standards work on agent security and identity ([FM-16.5](16-other-methods.md#fm-165-standards-work-on-agents)). |

## Coordination research

| Source | Cited for |
|---|---|
| A. Romero Vicente, *Coordinated Inauthentic Behaviour detection tree*, EU DisinfoLab, 8 August 2024. <https://www.disinfo.eu/publications/coordinated-inauthentic-behaviour-detection-tree/> | Separate coordination, source, impact and authenticity assessments ([FM-16.3](16-other-methods.md#fm-163-analytic-and-coordination-frameworks)). |
| E. T. Brooking, A. Kann, M. Rizzuto et al., *Dichotomies of Disinformation: Project Overview and Codebook*, DFRLab and Jigsaw. <https://github.com/DFRLab/Dichotomies-of-Disinformation> | Attribution and intent coded apart ([FM-16.3](16-other-methods.md#fm-163-analytic-and-coordination-frameworks)). |
| K. Mukherjee, C. G. Akcora, M. Kantarcioglu, "MoltGraph: A Longitudinal Temporal Graph Dataset of Moltbook for Coordinated-Agent Detection", arXiv:2603.00646, 2026. <https://arxiv.org/abs/2603.00646> | Short coordination bursts ([FM-16.4](16-other-methods.md#fm-164-research-on-agent-coordination-and-fingerprints)). |
| W. Lugoloobi, S. Marro, J. Magomere, J. Wright, C. Russell, "Known By Their Actions: Fingerprinting LLM Browser Agents via UI Traces", arXiv:2605.14786, 2026. <https://arxiv.org/abs/2605.14786> | Model fingerprints from interaction traces ([FM-16.4](16-other-methods.md#fm-164-research-on-agent-coordination-and-fingerprints)). |

## Statistics

| Source | Cited for |
|---|---|
| E. B. Wilson, "Probable inference, the law of succession, and statistical inference", *Journal of the American Statistical Association* 22(158), 1927, 209–212. <https://doi.org/10.1080/01621459.1927.10502953> | Wilson score intervals ([FM-9.5](09-evaluation.md#fm-95-detection-metrics)). |
| A. Bagga, B. Baldwin, "Algorithms for scoring coreference chains", *LREC Workshop on Linguistic Coreference*, 1998. | B-cubed precision and recall ([FM-9.6](09-evaluation.md#fm-96-cluster-metrics)). |
| E. Amigó, J. Gonzalo, J. Artiles, F. Verdejo, "A comparison of extrinsic clustering evaluation metrics based on formal constraints", *Information Retrieval* 12(4), 2009, 461–486. <https://doi.org/10.1007/s10791-008-9066-8> | Why B-cubed suits cluster evaluation ([FM-9.6](09-evaluation.md#fm-96-cluster-metrics)). |
| J. Cohen, "A coefficient of agreement for nominal scales", *Educational and Psychological Measurement* 20(1), 1960, 37–46. <https://doi.org/10.1177/001316446002000104> | Cohen's κ ([FM-9.8](09-evaluation.md#fm-98-inter-rater-agreement)). |
| J. L. Fleiss, "Measuring nominal scale agreement among many raters", *Psychological Bulletin* 76(5), 1971, 378–382. <https://doi.org/10.1037/h0031619> | Fleiss' κ ([FM-9.8](09-evaluation.md#fm-98-inter-rater-agreement)). |

## Interoperability

| Source | Cited for |
|---|---|
| OASIS, *STIX Version 2.1*, OASIS Standard, 10 June 2021. <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html> | The export profile; extension definitions (§7.3) and custom object naming ([chapter 12](12-interoperability.md)). |
| Responsible AI Collaborative, *AI Incident Database* and its editors' guide. <https://incidentdatabase.ai/editors-guide/> | Report and incident fields ([FM-12.3](12-interoperability.md#fm-123-ai-incident-databases)). |
| OECD, *Towards a common reporting framework for AI incidents*, OECD Artificial Intelligence Papers, 2025. <https://www.oecd.org/en/publications/towards-a-common-reporting-framework-for-ai-incidents_f326d4ac-en.html> | The 29-criterion common reporting framework and its dimensions ([FM-12.3](12-interoperability.md#fm-123-ai-incident-databases), [FM-12.4](12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks)). |
| OECD.AI, *AI Incidents and Hazards Monitor*, methodology. <https://oecd.ai/en/incidents-methodology> | AIM's definitions and planned submission process ([FM-12.3](12-interoperability.md#fm-123-ai-incident-databases)). |
| AI Vulnerability Database (AVID), framework documentation. <https://docs.avidml.org/database/framework/base-classes> | Report types and taxonomy ([FM-12.3](12-interoperability.md#fm-123-ai-incident-databases)). |
