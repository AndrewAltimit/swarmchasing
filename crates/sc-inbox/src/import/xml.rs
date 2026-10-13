//! A small XML tree for IODEF, read with `quick-xml` under caps.
//!
//! Refused outright: a DOCTYPE (so no entity can be declared, and none
//! expanded), any entity reference other than the five predefined ones and
//! character references (resolved here, never by a resolver that could
//! expand one), nesting deeper than [`Caps::max_depth`], more than
//! [`MAX_NODES`] elements, and any text or attribute value longer than
//! [`Caps::max_chars`]. Comments and processing instructions are skipped;
//! namespaces are dropped to local names.

use super::short;
use crate::spec::Caps;
use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Elements in one document.
pub const MAX_NODES: usize = 20_000;

/// One element: its local name, attributes, text, and children.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    /// Unique within the document, in document order.
    pub id: usize,
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// The element's own text (CDATA and references included), trimmed.
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Children named `name`.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Every node of the subtree, this one first.
    pub fn walk(&self) -> Vec<&Node> {
        let mut out = vec![self];
        let mut i = 0;
        while i < out.len() {
            let n = out[i];
            out.extend(n.children.iter());
            i += 1;
        }
        out
    }
}

/// Parse `text` into its root element under `caps`.
pub fn parse(text: &str, caps: &Caps) -> Result<Node, Vec<String>> {
    let err = |m: String| Err(vec![m]);
    let head: String = text
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_uppercase();
    if head.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return err("a DOCTYPE or entity declaration is refused".into());
    }
    let mut r = Reader::from_str(text);
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut next = 0usize;
    let long = |s: &str| s.chars().count() > caps.max_chars;
    let too_long = || err(format!("text longer than {} characters", caps.max_chars));
    loop {
        let ev = match r.read_event() {
            Ok(e) => e,
            Err(e) => return err(format!("not valid XML: {e}")),
        };
        let empty = matches!(ev, Event::Empty(_));
        match ev {
            Event::Start(e) | Event::Empty(e) => {
                if root.is_some() {
                    return err("more than one root element".into());
                }
                if stack.len() + 1 > caps.max_depth {
                    return err(format!("elements nested deeper than {}", caps.max_depth));
                }
                if next >= MAX_NODES {
                    return err(format!("more than {MAX_NODES} elements"));
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let mut attrs = Vec::new();
                for a in e.attributes() {
                    let a = match a {
                        Ok(a) => a,
                        Err(x) => return err(format!("not valid XML: {x}")),
                    };
                    let k = String::from_utf8_lossy(a.key.local_name().as_ref()).into_owned();
                    // Only the predefined entities and character references
                    // resolve; any other reference is an error.
                    let v = match a.normalized_value(XmlVersion::Implicit1_0) {
                        Ok(v) => v.into_owned(),
                        Err(x) => return err(format!("not valid XML: {x}")),
                    };
                    if long(&v) {
                        return err(format!(
                            "an attribute of <{name}> is longer than {} characters",
                            caps.max_chars
                        ));
                    }
                    attrs.push((k, v));
                }
                let node = Node {
                    id: next,
                    name,
                    attrs,
                    ..Node::default()
                };
                next += 1;
                if empty {
                    close(node, &mut stack, &mut root);
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                let Some(mut node) = stack.pop() else {
                    return err("an end tag with no start".into());
                };
                let t = node.text.trim();
                if long(t) {
                    return too_long();
                }
                node.text = t.to_string();
                close(node, &mut stack, &mut root);
            }
            Event::Text(t) => {
                let s = match t.xml10_content() {
                    Ok(s) => s.into_owned(),
                    Err(x) => return err(format!("not valid XML: {x}")),
                };
                if !add_text(&mut stack, &s, caps.max_chars) {
                    return too_long();
                }
            }
            Event::CData(c) => {
                let s = String::from_utf8_lossy(&c.into_inner()).into_owned();
                if !add_text(&mut stack, &s, caps.max_chars) {
                    return too_long();
                }
            }
            Event::GeneralRef(g) => {
                let name = match g.decode() {
                    Ok(n) => n.into_owned(),
                    Err(x) => return err(format!("not valid XML: {x}")),
                };
                let c = match g.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    Ok(None) => match resolve_predefined_entity(&name) {
                        Some(c) => c.to_string(),
                        None => {
                            return err(format!(
                                "not valid XML: the entity reference &{}; is not one of the predefined five",
                                short(&name, 40)
                            ));
                        }
                    },
                    Err(x) => return err(format!("not valid XML: {x}")),
                };
                if !add_text(&mut stack, &c, caps.max_chars) {
                    return too_long();
                }
            }
            Event::DocType(_) => return err("a DOCTYPE is refused".into()),
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return err("an element is not closed".into());
    }
    root.ok_or_else(|| vec!["no root element".to_string()])
}

fn close(node: Node, stack: &mut [Node], root: &mut Option<Node>) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => *root = Some(node),
    }
}

/// Text outside any element is ignored, and so is whitespace before an
/// element's first text (the indentation of containers). Returns false when
/// the text grows well past `max` (the exact cap is checked at the end tag).
fn add_text(stack: &mut [Node], s: &str, max: usize) -> bool {
    let Some(n) = stack.last_mut() else {
        return true;
    };
    if n.text.is_empty() && s.trim().is_empty() {
        return true;
    }
    n.text.push_str(s);
    n.text.len() <= max.saturating_mul(4)
}
