//! HTTP Message Signatures (RFC 9421) as the Web Bot Auth profile uses them:
//! read the `Signature-Input`, `Signature` and `Signature-Agent` headers a
//! record carries, rebuild the signature base, find the key in a directory
//! held from the provider's documentation, and check an Ed25519 signature.
//!
//! Only directories passed in are used. A `Signature-Agent` URI comes from
//! the request and is never fetched (FM-2.1, FM-7.11): this module has no
//! I/O, and the collector fetches only the catalog's directory URLs.
//!
//! Verification needs the `signatures` feature (the `ed25519-dalek` crate).
//! Without it every signature is reported as present and unverified.

use super::sfv::{self, Bare, Item, Member, Params};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The `tag` the Web Bot Auth profile requires.
pub const WEB_BOT_AUTH: &str = "web-bot-auth";

/// Clock skew allowed between a signature's `created` and the record's time.
const SKEW_SECS: i64 = 300;

/// One public key from a directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirKey {
    /// The RFC 7638 / RFC 8037 JWK SHA-256 thumbprint, base64url: what the
    /// Web Bot Auth profile puts in `keyid`.
    pub thumbprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub crv: String,
    /// The public key, base64url as the JWK carries it.
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

/// A provider's key directory as fetched from the address its documentation
/// gives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyDirectory {
    /// The catalog's id for it (`openai.chatgpt`).
    pub id: String,
    /// The `Signature-Agent` URI the provider documents for it.
    pub signature_agent: String,
    /// When it was fetched (`yyyy-mm-dd`), set by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched: Option<String>,
    pub keys: Vec<DirKey>,
}

/// The JWK thumbprint of an Ed25519 public key (RFC 8037 Appendix A.3):
/// SHA-256 over the required members in lexical order, base64url.
pub fn ed25519_thumbprint(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

impl KeyDirectory {
    /// Parse a JWK Set (`{"keys": [...]}`). Keys other than Ed25519 are
    /// skipped; a directory with none is an error.
    pub fn parse(id: &str, signature_agent: &str, text: &str) -> Result<KeyDirectory, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("{id}: not JSON: {e}"))?;
        let keys = v
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| format!("{id}: no `keys` array"))?;
        let s =
            |k: &serde_json::Value, f: &str| k.get(f).and_then(|x| x.as_str()).map(String::from);
        let keys: Vec<DirKey> = keys
            .iter()
            .filter(|k| s(k, "kty").as_deref() == Some("OKP"))
            .filter(|k| s(k, "crv").as_deref() == Some("Ed25519"))
            .filter_map(|k| {
                let x = s(k, "x")?;
                (URL_SAFE_NO_PAD.decode(&x).ok()?.len() == 32).then(|| DirKey {
                    thumbprint: ed25519_thumbprint(&x),
                    kid: s(k, "kid"),
                    crv: "Ed25519".into(),
                    x,
                    nbf: k.get("nbf").and_then(|n| n.as_i64()),
                    exp: k.get("exp").and_then(|n| n.as_i64()),
                })
            })
            .collect();
        if keys.is_empty() {
            return Err(format!("{id}: no Ed25519 keys in the directory"));
        }
        Ok(KeyDirectory {
            id: id.to_string(),
            signature_agent: signature_agent.to_string(),
            fetched: None,
            keys,
        })
    }

    fn key(&self, keyid: &str) -> Option<&DirKey> {
        self.keys
            .iter()
            .find(|k| k.thumbprint == keyid || k.kid.as_deref() == Some(keyid))
    }
}

/// A request as the signature sees it.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    /// `None` when the record does not say (an `@method` component then
    /// cannot be checked).
    pub method: Option<&'a str>,
    /// The absolute target URI.
    pub url: &'a str,
    pub headers: &'a BTreeMap<String, String>,
}

impl<'a> Message<'a> {
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the request carries message-signature headers at all.
    pub fn signed(&self) -> bool {
        self.header("signature-input").is_some() || self.header("signature").is_some()
    }
}

/// What checking a signature found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", content = "detail")]
pub enum Outcome {
    /// The signature verifies with a key from the named directory.
    Verified { directory: String },
    /// Malformed, expired at the request's time, or a bad signature.
    Failed(String),
    /// Could not be checked: no directory held for the signer, a key not in
    /// the directory as fetched, an unsupported algorithm or component.
    Unverified(String),
}

/// One signature on a request and what checking it found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigCheck {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// The `Signature-Agent` URI the request names, if any. Never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub outcome: Outcome,
}

/// Origin form of a URI for comparison: lower case, no trailing slash.
pub(crate) fn origin(uri: &str) -> String {
    uri.trim().trim_end_matches('/').to_ascii_lowercase()
}

struct Target<'a> {
    scheme: String,
    authority: String,
    path: &'a str,
    query: Option<&'a str>,
}

fn target(url: &str) -> Option<Target<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = rest[..end]
        .rsplit('@')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let default = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match auth.strip_suffix(default) {
        Some(a) if !default.is_empty() => a.to_string(),
        _ => auth,
    };
    let rest = &rest[end..];
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    Some(Target {
        scheme,
        authority,
        path,
        query,
    })
}

/// How a `;key=` member is written into the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberForm {
    /// Serialised, as RFC 9421 Section 2.1.2 says: a string keeps its quotes.
    Canonical,
    /// A string member's bare value. The Web Bot Auth draft's own vector
    /// (draft-meunier-web-bot-auth-architecture-05 A.2.2) is signed this way
    /// though its printed base shows quotes, so signers built on it may be
    /// too. Tried only after the canonical form fails.
    BareString,
}

/// The value of one covered component, or why it cannot be read.
fn component(msg: &Message, c: &Item, form: MemberForm) -> Result<String, Outcome> {
    let name = c
        .bare
        .as_str()
        .filter(|_| matches!(c.bare, Bare::String(_)))
        .ok_or_else(|| Outcome::Failed("a covered component is not a string".into()))?;
    if let Some(derived) = name.strip_prefix('@') {
        if !c.params.is_empty() {
            return Err(Outcome::Unverified(format!(
                "parameters on @{derived} are not supported"
            )));
        }
        let t = target(msg.url)
            .ok_or_else(|| Outcome::Unverified("the record's URL is not absolute".into()))?;
        let path = if t.path.is_empty() { "/" } else { t.path };
        return Ok(match derived {
            "method" => msg
                .method
                .ok_or_else(|| {
                    Outcome::Unverified("the record does not give the request method".into())
                })?
                .to_string(),
            "authority" => t.authority,
            "scheme" => t.scheme,
            "target-uri" => msg.url.split('#').next().unwrap_or("").to_string(),
            "path" => path.to_string(),
            "query" => format!("?{}", t.query.unwrap_or("")),
            "request-target" => match t.query {
                Some(q) => format!("{path}?{q}"),
                None => path.to_string(),
            },
            other => {
                return Err(Outcome::Unverified(format!(
                    "component @{other} is not supported"
                )));
            }
        });
    }
    if c.params.iter().any(|(k, _)| k != "key") {
        return Err(Outcome::Unverified(format!(
            "parameters on `{name}` are not supported"
        )));
    }
    let value = msg
        .header(name)
        .ok_or_else(|| Outcome::Failed(format!("covered header `{name}` is missing")))?;
    match c.param("key") {
        None => Ok(value.trim().to_string()),
        Some(k) => {
            let k = k.as_str().unwrap_or("");
            let d = sfv::dictionary(value.trim())
                .map_err(|e| Outcome::Failed(format!("`{name}` is not a dictionary: {e}")))?;
            d.iter()
                .find(|(m, _)| m == k)
                .map(|(_, m)| match (form, m) {
                    (
                        MemberForm::BareString,
                        Member::Item(Item {
                            bare: Bare::String(s),
                            ..
                        }),
                    ) => s.clone(),
                    _ => sfv::ser_member(m),
                })
                .ok_or_else(|| Outcome::Failed(format!("`{name}` has no member `{k}`")))
        }
    }
}

/// The signature base for the covered `components` and `params`
/// (RFC 9421 Section 2.5).
pub fn signature_base(
    msg: &Message,
    components: &[Item],
    params: &Params,
) -> Result<String, Outcome> {
    base(msg, components, params, MemberForm::Canonical)
}

fn base(
    msg: &Message,
    components: &[Item],
    params: &Params,
    form: MemberForm,
) -> Result<String, Outcome> {
    let mut s = String::new();
    for c in components {
        let v = component(msg, c, form)?;
        s.push_str(&sfv::ser_item(c));
        s.push_str(": ");
        s.push_str(&v);
        s.push('\n');
    }
    s.push_str("\"@signature-params\": ");
    s.push_str(&sfv::ser_member(&Member::Inner(
        components.to_vec(),
        params.clone(),
    )));
    Ok(s)
}

/// The `Signature-Agent` URI the signature names: the member its covered
/// `signature-agent;key=` component picks, else the header's first member,
/// else the legacy single string.
fn signature_agent(msg: &Message, components: &[Item]) -> Option<String> {
    let raw = msg.header("signature-agent")?.trim();
    let picked = components.iter().find_map(|c| {
        (c.bare.as_str()?.eq_ignore_ascii_case("signature-agent"))
            .then(|| c.param("key").and_then(Bare::as_str).map(str::to_string))
            .flatten()
    });
    if let Ok(d) = sfv::dictionary(raw) {
        let m = match &picked {
            Some(k) => d.iter().find(|(x, _)| x == k),
            None => d.first(),
        };
        if let Some((_, Member::Item(i))) = m
            && let Some(s) = i.bare.as_str()
        {
            return Some(s.to_string());
        }
    }
    sfv::item(raw)
        .ok()
        .and_then(|i| i.bare.as_str().map(str::to_string))
}

/// Check the request's signature at the record's time `ts` (Unix seconds;
/// `0` skips the time checks) against `directories`. `None` when the request
/// carries no signature. A request with several signatures is judged by its
/// Web Bot Auth one, else its first.
pub fn check(msg: &Message, ts: i64, directories: &[&KeyDirectory]) -> Option<SigCheck> {
    if !msg.signed() {
        return None;
    }
    let fail = |label: &str, why: String| SigCheck {
        label: label.to_string(),
        tag: None,
        keyid: None,
        agent: None,
        outcome: Outcome::Failed(why),
    };
    let Some(input) = msg.header("signature-input") else {
        return Some(fail(
            "",
            "a Signature header with no Signature-Input".into(),
        ));
    };
    let inputs = match sfv::dictionary(input.trim()) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => return Some(fail("", "an empty Signature-Input".into())),
        Err(e) => return Some(fail("", format!("Signature-Input does not parse: {e}"))),
    };
    let pick = inputs
        .iter()
        .find(|(_, m)| {
            matches!(m, Member::Inner(_, p) if sfv::param(p, "tag").and_then(Bare::as_str) == Some(WEB_BOT_AUTH))
        })
        .unwrap_or(&inputs[0]);
    let (label, member) = pick;
    let Member::Inner(components, params) = member else {
        return Some(fail(
            label,
            "the Signature-Input member is not an inner list".into(),
        ));
    };
    let get = |k: &str| sfv::param(params, k);
    let mut out = SigCheck {
        label: label.clone(),
        tag: get("tag").and_then(Bare::as_str).map(str::to_string),
        keyid: get("keyid").and_then(Bare::as_str).map(str::to_string),
        agent: signature_agent(msg, components),
        outcome: Outcome::Unverified(String::new()),
    };
    out.outcome = judge(msg, ts, directories, &out, components, params);
    Some(out)
}

fn judge(
    msg: &Message,
    ts: i64,
    directories: &[&KeyDirectory],
    sc: &SigCheck,
    components: &[Item],
    params: &Params,
) -> Outcome {
    let get = |k: &str| sfv::param(params, k);
    let sig = msg
        .header("signature")
        .map(|v| sfv::dictionary(v.trim()))
        .and_then(Result::ok)
        .and_then(|d| d.into_iter().find(|(l, _)| *l == sc.label))
        .and_then(|(_, m)| match m {
            Member::Item(Item {
                bare: Bare::Bytes(b),
                ..
            }) => Some(b),
            _ => None,
        });
    let Some(sig) = sig else {
        return Outcome::Failed(format!("no Signature value for label `{}`", sc.label));
    };
    let created = get("created").and_then(Bare::as_int);
    let expires = get("expires").and_then(Bare::as_int);
    if sc.tag.as_deref() == Some(WEB_BOT_AUTH) {
        if created.is_none() || expires.is_none() || sc.keyid.is_none() {
            return Outcome::Failed("Web Bot Auth requires created, expires and keyid".into());
        }
        let covers = components
            .iter()
            .any(|c| matches!(c.bare.as_str(), Some("@authority" | "@target-uri")));
        if !covers {
            return Outcome::Failed(
                "Web Bot Auth requires @authority or @target-uri to be covered".into(),
            );
        }
    }
    if ts > 0 {
        if created.is_some_and(|c| c > ts + SKEW_SECS) {
            return Outcome::Failed("created after the request's time".into());
        }
        if expires.is_some_and(|e| e < ts) {
            return Outcome::Failed("expired before the request's time (a replay?)".into());
        }
    }
    if let Some(alg) = get("alg").and_then(Bare::as_str)
        && alg != "ed25519"
    {
        return Outcome::Unverified(format!("algorithm `{alg}` is not supported"));
    }
    let Some(keyid) = &sc.keyid else {
        return Outcome::Unverified("no keyid".into());
    };
    let candidates: Vec<&&KeyDirectory> = match &sc.agent {
        Some(a) => directories
            .iter()
            .filter(|d| origin(&d.signature_agent) == origin(a))
            .collect(),
        None => directories.iter().collect(),
    };
    if candidates.is_empty() {
        return Outcome::Unverified(match &sc.agent {
            Some(_) => {
                "no directory held for the signer it names (never fetched from the request)".into()
            }
            None => "no key directories held".into(),
        });
    }
    let Some((dir, key)) = candidates
        .iter()
        .find_map(|d| d.key(keyid).map(|k| (*d, k)))
    else {
        return Outcome::Unverified(
            "key not in the directory as fetched (rotated, or not the signer's)".into(),
        );
    };
    if ts > 0 && (key.nbf.is_some_and(|n| n > ts) || key.exp.is_some_and(|e| e < ts)) {
        return Outcome::Failed("the key was not valid at the request's time".into());
    }
    let Ok(pk) = URL_SAFE_NO_PAD.decode(&key.x) else {
        return Outcome::Unverified("the directory key does not decode".into());
    };
    let keyed = components.iter().any(|c| c.param("key").is_some());
    let forms: &[MemberForm] = if keyed {
        &[MemberForm::Canonical, MemberForm::BareString]
    } else {
        &[MemberForm::Canonical]
    };
    for &form in forms {
        let b = match base(msg, components, params, form) {
            Ok(b) => b,
            Err(o) => return o,
        };
        match verify_ed25519(&pk, b.as_bytes(), &sig) {
            Some(true) => {
                return Outcome::Verified {
                    directory: dir.id.clone(),
                };
            }
            Some(false) => {}
            None => return Outcome::Unverified("signature verification is not built in".into()),
        }
    }
    Outcome::Failed("the signature does not verify".into())
}

/// Ed25519 (RFC 8032) verification, strict: `None` when not built.
#[cfg(feature = "signatures")]
pub fn verify_ed25519(public: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(public), <[u8; 64]>::try_from(sig)) else {
        return Some(false);
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Some(false);
    };
    Some(vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok())
}

/// Ed25519 verification is not built: every signature stays unverified.
#[cfg(not(feature = "signatures"))]
pub fn verify_ed25519(_public: &[u8], _msg: &[u8], _sig: &[u8]) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9421 Appendix B.1.4, test-key-ed25519 (public half).
    const TEST_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

    fn dir() -> KeyDirectory {
        let jwks = format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_X}"}}]}}"#);
        KeyDirectory::parse("test", "https://signature-agent.test", &jwks).unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn thumbprint_matches_the_web_bot_auth_vectors() {
        assert_eq!(
            ed25519_thumbprint(TEST_X),
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
        );
    }

    /// RFC 9421 Appendix B.2.6: the signature base, and the signature.
    #[test]
    fn rfc9421_b26_ed25519() {
        let h = headers(&[
            ("Host", "example.com"),
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
            ("Content-Length", "18"),
            (
                "Signature-Input",
                r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
            ),
            (
                "Signature",
                "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
            ),
        ]);
        let msg = Message {
            method: Some("POST"),
            url: "https://example.com/foo?param=Value&Pet=dog",
            headers: &h,
        };
        let d = sfv::dictionary(h["Signature-Input"].as_str()).unwrap();
        let Member::Inner(c, p) = &d[0].1 else {
            panic!()
        };
        assert_eq!(
            signature_base(&msg, c, p).unwrap(),
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
        );
        // The keyid is the RFC's name for the key, which the directory
        // carries as its `kid`.
        let jwks = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","x":"{TEST_X}"}}]}}"#
        );
        let d = KeyDirectory::parse("rfc", "https://example.com", &jwks).unwrap();
        let r = check(&msg, 1618884473, &[&d]).unwrap();
        if cfg!(feature = "signatures") {
            assert_eq!(
                r.outcome,
                Outcome::Verified {
                    directory: "rfc".into()
                }
            );
        } else {
            assert!(matches!(r.outcome, Outcome::Unverified(_)));
        }
    }

    fn wba_a22(sig: &str) -> BTreeMap<String, String> {
        headers(&[
            (
                "Signature-Agent",
                r#"agent2="https://signature-agent.test""#,
            ),
            (
                "Signature-Input",
                r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1MptpENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg==";tag="web-bot-auth""#,
            ),
            ("Signature", sig),
        ])
    }

    const A22_SIG: &str = "sig2=:DGiW2ErlQh0hc8wY2FQdbnFd6CEmonyY8nlvECIJFaUSYYNvNvSsGyP99BUGtq51gA4ouXlkUwjnta084bpjCg==:";

    /// draft-meunier-web-bot-auth-architecture-05 Appendix A.2.2.
    #[test]
    fn web_bot_auth_a22_dictionary_agent() {
        let h = wba_a22(A22_SIG);
        let msg = Message {
            method: Some("POST"),
            url: "https://example.com/foo?param=Value&Pet=dog",
            headers: &h,
        };
        let d = dir();
        let r = check(&msg, 1_735_690_000, &[&d]).unwrap();
        assert_eq!(r.tag.as_deref(), Some(WEB_BOT_AUTH));
        assert_eq!(r.agent.as_deref(), Some("https://signature-agent.test"));
        if cfg!(feature = "signatures") {
            assert_eq!(
                r.outcome,
                Outcome::Verified {
                    directory: "test".into()
                }
            );
            // Another host: the base changes and the signature fails.
            let moved = Message {
                url: "https://other.example/foo",
                ..msg
            };
            assert!(matches!(
                check(&moved, 1_735_690_000, &[&d]).unwrap().outcome,
                Outcome::Failed(_)
            ));
            // One flipped byte of signature.
            let h = wba_a22(&A22_SIG.replace("DGiW", "DGiX"));
            let bad = Message { headers: &h, ..msg };
            assert_eq!(
                check(&bad, 1_735_690_000, &[&d]).unwrap().outcome,
                Outcome::Failed("the signature does not verify".into())
            );
        }
        // Before `created` (beyond skew) the signature is out of time.
        assert!(matches!(
            check(&msg, 1_700_000_000, &[&d]).unwrap().outcome,
            Outcome::Failed(_)
        ));
        // A signer with no directory held stays unverified: never fetched.
        assert!(matches!(
            check(&msg, 1_735_690_000, &[]).unwrap().outcome,
            Outcome::Unverified(_)
        ));
    }

    /// Appendix A.2.3: the legacy single-string `Signature-Agent`.
    #[test]
    fn web_bot_auth_a23_legacy_agent() {
        let h = headers(&[
            ("Signature-Agent", r#""https://signature-agent.test""#),
            (
                "Signature-Input",
                r#"sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth""#,
            ),
            (
                "Signature",
                "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
            ),
        ]);
        let msg = Message {
            method: None,
            url: "https://example.com/foo",
            headers: &h,
        };
        let d = dir();
        let r = check(&msg, 1_735_690_000, &[&d]).unwrap();
        assert_eq!(r.agent.as_deref(), Some("https://signature-agent.test"));
        if cfg!(feature = "signatures") {
            assert_eq!(
                r.outcome,
                Outcome::Verified {
                    directory: "test".into()
                }
            );
        }
        // After `expires`: a replay.
        assert!(matches!(
            check(&msg, 1_735_700_000, &[&d]).unwrap().outcome,
            Outcome::Failed(_)
        ));
    }

    /// Appendix A.2.1: no `Signature-Agent`; every held directory is tried.
    #[test]
    fn web_bot_auth_a21_no_agent() {
        let h = headers(&[
            (
                "Signature-Input",
                r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==";tag="web-bot-auth""#,
            ),
            (
                "Signature",
                "sig1=:FFASViSdcgsyaqqYiCnkHreeZzbNKcTzDvZC5uVlP/dn9IbWj8j0o4wKFTH3rBnUiSUBduwm1Gp5VlIPCp01Ag==:",
            ),
        ]);
        let msg = Message {
            method: None,
            url: "https://example.com:443/foo",
            headers: &h,
        };
        let d = dir();
        let r = check(&msg, 0, &[&d]).unwrap();
        assert_eq!(r.agent, None);
        if cfg!(feature = "signatures") {
            assert_eq!(
                r.outcome,
                Outcome::Verified {
                    directory: "test".into()
                }
            );
        }
    }

    #[test]
    fn malformed_and_unsigned() {
        let h = headers(&[("User-Agent", "x")]);
        let msg = Message {
            method: None,
            url: "https://a.example/",
            headers: &h,
        };
        assert!(check(&msg, 0, &[]).is_none());
        let h = headers(&[
            ("Signature-Input", "sig=garbage("),
            ("Signature", "sig=:AA==:"),
        ]);
        let msg = Message { headers: &h, ..msg };
        assert!(matches!(
            check(&msg, 0, &[]).unwrap().outcome,
            Outcome::Failed(_)
        ));
        assert!(KeyDirectory::parse("x", "https://a.test", r#"{"keys":[{"kty":"RSA"}]}"#).is_err());
        assert_eq!(
            target("https://A.Example:443/p?q#f").unwrap().authority,
            "a.example"
        );
        assert_eq!(
            target("http://u@a.example:8080").unwrap().authority,
            "a.example:8080"
        );
    }
}
