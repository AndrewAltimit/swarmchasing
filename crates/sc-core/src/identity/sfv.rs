//! The part of HTTP Structured Field Values (RFC 8941) that message
//! signatures need: dictionaries whose members are items or inner lists,
//! with parameters, and their canonical serialisation.
//!
//! RFC 9421 builds the `@signature-params` line and every `;key=` component
//! from the serialised form, so parsing and serialising must round-trip the
//! canonical text exactly. Decimals are parsed and kept as written.

/// A bare item.
#[derive(Debug, Clone, PartialEq)]
pub enum Bare {
    Integer(i64),
    /// Kept as written: RFC 8941 decimals have at most three fraction digits.
    Decimal(String),
    String(String),
    Token(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

pub type Params = Vec<(String, Bare)>;

/// An item with its parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub bare: Bare,
    pub params: Params,
}

/// A dictionary member: an item or an inner list.
#[derive(Debug, Clone, PartialEq)]
pub enum Member {
    Item(Item),
    Inner(Vec<Item>, Params),
}

impl Item {
    pub fn param(&self, key: &str) -> Option<&Bare> {
        param(&self.params, key)
    }
}

pub fn param<'a>(params: &'a Params, key: &str) -> Option<&'a Bare> {
    params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

impl Bare {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Bare::String(s) | Bare::Token(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Bare::Integer(n) => Some(*n),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

type R<T> = Result<T, String>;

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }

    fn ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn key(&mut self) -> R<String> {
        let start = self.i;
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() || c == b'*' => self.i += 1,
            _ => return Err(format!("expected a key at {}", self.i)),
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c) {
                self.i += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn bare(&mut self) -> R<Bare> {
        match self.peek() {
            Some(b'"') => self.string(),
            Some(b':') => self.bytes(),
            Some(b'?') => {
                self.i += 1;
                let v = match self.peek() {
                    Some(b'1') => true,
                    Some(b'0') => false,
                    _ => return Err("bad boolean".into()),
                };
                self.i += 1;
                Ok(Bare::Boolean(v))
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => self.token(),
            _ => Err(format!("expected an item at {}", self.i)),
        }
    }

    fn string(&mut self) -> R<Bare> {
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(Bare::String(out));
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => out.push(c as char),
                        _ => return Err("bad escape in string".into()),
                    }
                    self.i += 1;
                }
                Some(c) if (0x20..0x7f).contains(&c) => {
                    out.push(c as char);
                    self.i += 1;
                }
                Some(_) => return Err("non-ASCII character in string".into()),
            }
        }
    }

    fn bytes(&mut self) -> R<Bare> {
        use base64::Engine;
        self.i += 1;
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b':' {
                break;
            }
            self.i += 1;
        }
        if self.peek() != Some(b':') {
            return Err("unterminated byte sequence".into());
        }
        let b64 = &self.s[start..self.i];
        self.i += 1;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map(Bare::Bytes)
            .map_err(|e| format!("byte sequence: {e}"))
    }

    fn number(&mut self) -> R<Bare> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut decimal = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.i += 1;
            } else if c == b'.' && !decimal {
                decimal = true;
                self.i += 1;
            } else {
                break;
            }
        }
        let text = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        if decimal {
            return Ok(Bare::Decimal(text));
        }
        if text.trim_start_matches('-').len() > 15 {
            return Err("integer too long".into());
        }
        text.parse()
            .map(Bare::Integer)
            .map_err(|_| format!("bad integer `{text}`"))
    }

    fn token(&mut self) -> R<Bare> {
        let start = self.i;
        self.i += 1;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c) {
                self.i += 1;
            } else {
                break;
            }
        }
        Ok(Bare::Token(
            String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
        ))
    }

    fn params(&mut self) -> R<Params> {
        let mut out = Params::new();
        while self.peek() == Some(b';') {
            self.i += 1;
            self.sp();
            let k = self.key()?;
            let v = if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare()?
            } else {
                Bare::Boolean(true)
            };
            match out.iter_mut().find(|(x, _)| *x == k) {
                Some(slot) => slot.1 = v,
                None => out.push((k, v)),
            }
        }
        Ok(out)
    }

    fn item(&mut self) -> R<Item> {
        let bare = self.bare()?;
        let params = self.params()?;
        Ok(Item { bare, params })
    }

    fn member(&mut self) -> R<Member> {
        if self.peek() != Some(b'(') {
            return self.item().map(Member::Item);
        }
        self.i += 1;
        let mut items = Vec::new();
        loop {
            self.sp();
            if self.peek() == Some(b')') {
                self.i += 1;
                let params = self.params()?;
                return Ok(Member::Inner(items, params));
            }
            items.push(self.item()?);
            match self.peek() {
                Some(b' ' | b')') => {}
                _ => return Err("bad inner list".into()),
            }
        }
    }
}

/// Parse a dictionary field value. Later duplicate keys replace earlier ones,
/// keeping the first position, as RFC 8941 says.
pub fn dictionary(s: &str) -> R<Vec<(String, Member)>> {
    let mut p = Parser {
        s: s.as_bytes(),
        i: 0,
    };
    let mut out: Vec<(String, Member)> = Vec::new();
    p.sp();
    if p.peek().is_none() {
        return Ok(out);
    }
    loop {
        let k = p.key()?;
        let m = if p.peek() == Some(b'=') {
            p.i += 1;
            p.member()?
        } else {
            Member::Item(Item {
                bare: Bare::Boolean(true),
                params: p.params()?,
            })
        };
        match out.iter_mut().find(|(x, _)| *x == k) {
            Some(slot) => slot.1 = m,
            None => out.push((k, m)),
        }
        p.ows();
        match p.peek() {
            None => return Ok(out),
            Some(b',') => {
                p.i += 1;
                p.ows();
                if p.peek().is_none() {
                    return Err("trailing comma".into());
                }
            }
            Some(_) => return Err(format!("unexpected character at {}", p.i)),
        }
    }
}

/// Parse an item field value (a legacy `Signature-Agent: "https://..."`).
pub fn item(s: &str) -> R<Item> {
    let mut p = Parser {
        s: s.trim().as_bytes(),
        i: 0,
    };
    let it = p.item()?;
    if p.i != p.s.len() {
        return Err("trailing characters after item".into());
    }
    Ok(it)
}

pub fn ser_bare(b: &Bare) -> String {
    use base64::Engine;
    match b {
        Bare::Integer(n) => n.to_string(),
        Bare::Decimal(d) => d.clone(),
        Bare::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Bare::Token(t) => t.clone(),
        Bare::Bytes(b) => format!(":{}:", base64::engine::general_purpose::STANDARD.encode(b)),
        Bare::Boolean(true) => "?1".into(),
        Bare::Boolean(false) => "?0".into(),
    }
}

pub fn ser_params(p: &Params) -> String {
    p.iter()
        .map(|(k, v)| match v {
            Bare::Boolean(true) => format!(";{k}"),
            v => format!(";{k}={}", ser_bare(v)),
        })
        .collect()
}

pub fn ser_item(i: &Item) -> String {
    format!("{}{}", ser_bare(&i.bare), ser_params(&i.params))
}

pub fn ser_member(m: &Member) -> String {
    match m {
        Member::Item(i) => ser_item(i),
        Member::Inner(items, params) => format!(
            "({}){}",
            items.iter().map(ser_item).collect::<Vec<_>>().join(" "),
            ser_params(params)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_input_round_trips() {
        let v = r#"sig1=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqk";alg="ed25519";tag="web-bot-auth", sig2=("@method");created=1"#;
        let d = dictionary(v).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(
            ser_member(&d[0].1),
            r#"("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqk";alg="ed25519";tag="web-bot-auth""#
        );
        let Member::Inner(items, params) = &d[0].1 else {
            panic!()
        };
        assert_eq!(items[1].param("key").and_then(Bare::as_str), Some("agent2"));
        assert_eq!(
            param(params, "created").and_then(Bare::as_int),
            Some(1735689600)
        );
    }

    #[test]
    fn items_bytes_and_errors() {
        let d = dictionary("sig=:AAEC:, ok, n=-3;x").unwrap();
        assert_eq!(
            d[0].1,
            Member::Item(Item {
                bare: Bare::Bytes(vec![0, 1, 2]),
                params: vec![]
            })
        );
        assert_eq!(ser_member(&d[1].1), "?1");
        assert_eq!(ser_member(&d[2].1), "-3;x");
        assert_eq!(
            item(r#""https://a.test""#).unwrap().bare.as_str(),
            Some("https://a.test")
        );
        for bad in ["Sig=1", "a=\"x", "a=(1 2", "a=1,", "a=:!!:"] {
            assert!(dictionary(bad).is_err(), "{bad}");
        }
        assert_eq!(ser_bare(&Bare::String("a\"b\\".into())), r#""a\"b\\""#);
    }
}
