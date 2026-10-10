//! Who a report is for, and the wording that differs between them: the
//! title, the summary and the requested action.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// The AI developer whose agents appear to be responsible.
    Provider,
    /// The operator of a targeted or compromised system.
    Affected,
    /// Our own case notes.
    #[default]
    Internal,
    /// The public notice: withholds callback channels, credential-like
    /// identifiers and attack details for compromised endpoints.
    Public,
}

impl std::str::FromStr for Audience {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "provider" => Ok(Self::Provider),
            "affected" | "victim" | "operator" => Ok(Self::Affected),
            "internal" => Ok(Self::Internal),
            "public" | "notice" => Ok(Self::Public),
            _ => Err(format!(
                "unknown audience `{s}` (provider|affected|internal|public)"
            )),
        }
    }
}

/// The report's title.
pub(super) fn title(audience: Audience) -> &'static str {
    match audience {
        Audience::Provider => "Report of suspected misaligned agent activity",
        Audience::Affected => "Notice: automated agent activity targeting your systems",
        Audience::Internal => "Case notes: agent activity",
        Audience::Public => "Public notice: suspected misaligned agent activity",
    }
}

/// The summary paragraph. `host_list` is the top target hosts, defanged.
pub(super) fn summary(audience: Audience, host_list: &[String]) -> String {
    match audience {
        Audience::Provider => format!(
            "We observed automated activity consistent with AI agents operating with little or no human oversight. \
             Based on the indicators below, we believe some of it may originate from agents built on or hosted by your platform. \
             Targets included {}.",
            if host_list.is_empty() {
                "unidentified hosts".into()
            } else {
                host_list.join(", ")
            }
        ),
        Audience::Affected => format!(
            "Public scan and archive records show automated agents sending requests to systems we believe you operate ({}). \
             We are sharing this so you can check your own logs. We have not confirmed whether any request succeeded.",
            if host_list.is_empty() {
                "see below".into()
            } else {
                host_list.join(", ")
            }
        ),
        Audience::Internal => format!("Targets: {}.", host_list.join(", ")),
        Audience::Public => format!(
            "Public scan and archive records show automated activity consistent with AI agents operating with little or no human oversight, aimed at {}. \
             Reports went to the AI provider and the affected operators when this notice was published. We have not confirmed whether any request succeeded.",
            if host_list.is_empty() {
                "unidentified hosts".into()
            } else {
                host_list.join(", ")
            }
        ),
    }
}

/// What the report asks its reader to do.
pub(super) fn requested_action(audience: Audience) -> &'static str {
    match audience {
        Audience::Provider => {
            "- Check whether these patterns match agents or sandboxes on your platform during the window above.\n\
             - If they do, stop the runs and review why the agents chose to probe or circumvent access controls.\n\
             - Let us know whether you can confirm or rule out involvement, so the public record can be corrected."
        }
        Audience::Affected => {
            "- Check your access logs for the window above and the parameters listed.\n\
             - Treat any request carrying attack payloads as an intrusion attempt and check whether it was handled safely.\n\
             - Rotate any credentials or API keys issued to throwaway accounts during this window.\n\
             - Contact us with questions; we will share raw record links on request."
        }
        Audience::Internal => {
            "- [ ] verify records\n- [ ] identify contacts (`swarmchase contact <domain>`)\n- [ ] send provider + affected notices"
        }
        Audience::Public => {
            "- If you operate a listed host, check your access logs for the window above and the indicators listed, and contact us for the full report.\n\
             - If you run an agent platform, check whether these patterns match your users' agents.\n\
             - If anything here is wrong, tell us: corrections are published on this page with their date."
        }
    }
}
