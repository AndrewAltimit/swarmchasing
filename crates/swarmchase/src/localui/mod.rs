//! Local pages for the admin's human-in-the-loop steps.
//!
//! An [`App`] serves its own script, style and JSON endpoints; this module
//! serves the page shell, the shared style and helpers (`ui.css`, `ui.js`),
//! and the checks every such page needs. Records shown on these pages are
//! attacker-written text, so:
//!
//! - the server listens on 127.0.0.1 only and answers only requests whose
//!   `Host` is that address or `localhost` on its port (no DNS rebinding);
//! - a `POST` needs the per-run token the shell carries and, when the browser
//!   sends one, a same-origin `Origin`;
//! - every response carries a content security policy that loads nothing but
//!   the page's own files, so no record value can load or run anything;
//! - the shared helpers build the page from text nodes only.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const SHELL: &str = include_str!("shell.html");
const UI_SCRIPT: &str = include_str!("ui.js");
const UI_STYLE: &str = include_str!("ui.css");

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// A page served by [`Server`].
pub trait App {
    /// The page title, as text.
    fn title(&self) -> String;
    /// The app's script, loaded after `ui.js`.
    fn script(&self) -> &'static str;
    /// The app's style, loaded after `ui.css`.
    fn style(&self) -> &'static str;
    /// `GET /api/<path>`; `None` is a 404.
    fn get(&mut self, path: &str) -> Option<Response>;
    /// `POST /api/<path>`, after the token and origin checks.
    fn post(&mut self, path: &str, body: &[u8], now: &str) -> Response;
}

/// A parsed request: method, path, lower-cased header names, body.
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, ctype: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            ctype,
            body: body.into(),
        }
    }

    pub fn json(status: u16, v: &Value) -> Self {
        Self::new(status, "application/json", v.to_string())
    }

    pub fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &json!({ "error": msg }))
    }
}

/// 128 random bits as hex, from the standard library's randomly seeded hasher.
fn token() -> String {
    let half = || {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        h.finish()
    };
    format!("{:016x}{:016x}", half(), half())
}

/// Text for an HTML text or attribute position.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub struct Server<A: App> {
    pub app: A,
    pub port: u16,
    token: String,
}

impl<A: App> Server<A> {
    pub fn new(app: A, port: u16) -> Self {
        Self {
            app,
            port,
            token: token(),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    #[cfg(test)]
    pub fn token(&self) -> &str {
        &self.token
    }

    fn host_ok(&self, req: &Request) -> bool {
        let p = self.port;
        req.header("host")
            .is_some_and(|h| h == format!("127.0.0.1:{p}") || h == format!("localhost:{p}"))
    }

    fn origin_ok(&self, req: &Request) -> bool {
        let p = self.port;
        req.header("origin").is_none_or(|o| {
            o == format!("http://127.0.0.1:{p}") || o == format!("http://localhost:{p}")
        })
    }

    pub fn handle(&mut self, req: &Request, now: &str) -> Response {
        if !self.host_ok(req) {
            return Response::error(403, "wrong host");
        }
        let js = "text/javascript; charset=utf-8";
        let css = "text/css; charset=utf-8";
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => Response::new(
                200,
                "text/html; charset=utf-8",
                SHELL
                    .replace("{{TITLE}}", &escape(&self.app.title()))
                    .replace("{{TOKEN}}", &self.token),
            ),
            ("GET", "/ui.js") => Response::new(200, js, UI_SCRIPT),
            ("GET", "/ui.css") => Response::new(200, css, UI_STYLE),
            ("GET", "/app.js") => Response::new(200, js, self.app.script()),
            ("GET", "/app.css") => Response::new(200, css, self.app.style()),
            ("GET", p) if p.starts_with("/api/") => self
                .app
                .get(&p["/api/".len()..])
                .unwrap_or_else(|| Response::error(404, "not found")),
            ("POST", p) if p.starts_with("/api/") => {
                if req.header("x-page-token") != Some(self.token.as_str()) || !self.origin_ok(req) {
                    return Response::error(403, "missing or wrong token");
                }
                self.app.post(&p["/api/".len()..], &req.body, now)
            }
            _ => Response::error(404, "not found"),
        }
    }

    /// Serve until the process is stopped.
    pub fn run(mut self, banner: &str) -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.port))
            .with_context(|| format!("listening on 127.0.0.1:{}", self.port))?;
        println!(
            "{banner}: {} (this machine only; Ctrl-C to stop)",
            self.url()
        );
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let resp = match read_request(&mut s) {
                Ok(req) => {
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
                    self.handle(&req, &now)
                }
                Err(_) => Response::error(400, "bad request"),
            };
            if let Err(e) = write_response(&mut s, &resp) {
                eprintln!("{banner}: {e:#}");
            }
        }
        Ok(())
    }
}

/// Read one request: headers up to 16 KiB, a body up to 1 MiB.
pub fn read_request(s: &mut TcpStream) -> Result<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 16 * 1024 {
            bail!("headers too large");
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            bail!("connection closed");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..end]).context("headers not UTF-8")?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if len > 1024 * 1024 {
        bail!("body too large");
    }
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

pub fn write_response(s: &mut TcpStream, r: &Response) -> Result<()> {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
Content-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        r.status,
        r.ctype,
        r.body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(&r.body)?;
    s.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    impl App for Echo {
        fn title(&self) -> String {
            "Echo <test>".into()
        }
        fn script(&self) -> &'static str {
            "/* app */"
        }
        fn style(&self) -> &'static str {
            "/* style */"
        }
        fn get(&mut self, path: &str) -> Option<Response> {
            (path == "ping").then(|| Response::json(200, &json!({"pong": true})))
        }
        fn post(&mut self, path: &str, body: &[u8], now: &str) -> Response {
            Response::json(200, &json!({"path": path, "len": body.len(), "now": now}))
        }
    }

    pub fn req(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    const HOST: (&str, &str) = ("host", "127.0.0.1:8765");

    #[test]
    fn host_token_and_origin_are_checked() {
        let mut s = Server::new(Echo, 8765);
        assert_eq!(s.handle(&req("GET", "/", &[], ""), "t").status, 403);
        assert_eq!(
            s.handle(&req("GET", "/", &[("host", "evil.example:8765")], ""), "t")
                .status,
            403,
            "DNS rebinding"
        );
        let page = s.handle(&req("GET", "/", &[HOST], ""), "t");
        assert_eq!(page.status, 200);
        let page = String::from_utf8(page.body).unwrap();
        assert!(page.contains(s.token()) && !page.contains("{{TOKEN}}"));
        assert!(page.contains("Echo &lt;test&gt;"), "title escaped");
        assert_eq!(
            s.handle(&req("GET", "/api/ping", &[HOST], ""), "t").status,
            200
        );
        assert_eq!(
            s.handle(&req("GET", "/api/nope", &[HOST], ""), "t").status,
            404
        );
        assert_eq!(
            s.handle(&req("POST", "/api/x", &[HOST], "{}"), "t").status,
            403
        );
        let tok = s.token().to_string();
        let cross = [
            HOST,
            ("x-page-token", tok.as_str()),
            ("origin", "https://evil.example"),
        ];
        assert_eq!(
            s.handle(&req("POST", "/api/x", &cross, "{}"), "t").status,
            403
        );
        let ok = [
            HOST,
            ("x-page-token", tok.as_str()),
            ("origin", "http://127.0.0.1:8765"),
        ];
        let r = s.handle(&req("POST", "/api/x", &ok, "{}"), "now");
        assert_eq!(r.status, 200);
        assert!(
            String::from_utf8(r.body)
                .unwrap()
                .contains("\"now\":\"now\"")
        );
    }

    #[test]
    fn serves_over_a_socket_with_the_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut s = Server::new(Echo, port);
        let t = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let req = read_request(&mut c).unwrap();
            let resp = s.handle(&req, "t");
            write_response(&mut c, &resp).unwrap();
        });
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            c,
            "GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        t.join().unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(out.contains("Content-Security-Policy: default-src 'none'"));
        assert!(out.contains("\"pong\":true"));
    }
}
