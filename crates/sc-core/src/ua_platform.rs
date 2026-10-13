//! The operating system a request's user agent names against the one its
//! `Sec-CH-UA-Platform` client hint names.
//!
//! Chromium sends the platform hint from the system it really runs on, while
//! a user agent is a string any client can set. A hosted browser that
//! presents a desktop user agent from another system shows the two apart:
//! a macOS user agent with a `"Linux"` hint, as observed for ChatGPT agent
//! (<https://simonwillison.net/2025/Aug/4/chatgpt-agents-user-agent/>). Only
//! the desktop systems are compared. Android's "desktop site" mode sends a
//! Linux user agent with an `"Android"` hint, and mobile emulation changes
//! both, so a mobile system on either side is never a mismatch.

/// The systems compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    ChromeOs,
    /// Android or iOS: never compared.
    Mobile,
}

/// The system a user agent names, if it names one.
pub fn of_user_agent(ua: &str) -> Option<Os> {
    let u = ua.to_ascii_lowercase();
    if u.contains("android") || u.contains("iphone") || u.contains("ipad") {
        Some(Os::Mobile)
    } else if u.contains("cros ") {
        Some(Os::ChromeOs)
    } else if u.contains("windows nt") || u.contains("win64") {
        Some(Os::Windows)
    } else if u.contains("macintosh") || u.contains("mac os x") {
        Some(Os::MacOs)
    } else if u.contains("linux") || u.contains("x11") {
        Some(Os::Linux)
    } else {
        None
    }
}

/// The system a `Sec-CH-UA-Platform` value names (quoted or not).
pub fn of_hint(value: &str) -> Option<Os> {
    match value
        .trim()
        .trim_matches('"')
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "windows" => Some(Os::Windows),
        "macos" => Some(Os::MacOs),
        "linux" => Some(Os::Linux),
        "chrome os" | "chromium os" => Some(Os::ChromeOs),
        "android" | "ios" => Some(Os::Mobile),
        _ => None,
    }
}

/// True when the user agent and the platform hint name two different
/// desktop systems.
pub fn mismatch(ua: &str, hint: &str) -> bool {
    match (of_user_agent(ua), of_hint(hint)) {
        (Some(a), Some(b)) => a != b && a != Os::Mobile && b != Os::Mobile,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
    const WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
    const LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
    const ANDROID: &str = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";
    const CROS: &str = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

    #[test]
    fn desktop_systems_apart_are_a_mismatch() {
        assert!(mismatch(MAC, "\"Linux\""));
        assert!(mismatch(WIN, "\"macOS\""));
        assert!(mismatch(LINUX, "\"Windows\""));
    }

    #[test]
    fn agreeing_mobile_and_unknown_values_are_not() {
        for (ua, hint) in [
            (MAC, "\"macOS\""),
            (WIN, "\"Windows\""),
            (LINUX, "\"Linux\""),
            (CROS, "\"Chrome OS\""),
            (CROS, "\"Chromium OS\""),
            (ANDROID, "\"Android\""),
            // Android's desktop-site mode: a Linux user agent, an Android hint.
            (LINUX, "\"Android\""),
            // Device emulation on a desktop: a phone user agent.
            (ANDROID, "\"macOS\""),
            (MAC, "\"Unknown\""),
            (MAC, ""),
            ("curl/8.5.0", "\"Linux\""),
        ] {
            assert!(!mismatch(ua, hint), "{ua} / {hint}");
        }
    }
}
