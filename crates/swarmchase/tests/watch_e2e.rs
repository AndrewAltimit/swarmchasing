//! Watch runs end to end against a fixture timemap server on 127.0.0.1: a
//! run cut short after collecting, the next run's digest reporting what it
//! stored, a late-indexed capture older than the analysis window, the
//! digest's `case add` line run as written, a changed query, `--only` and
//! `watch reset`. No request leaves the machine.

use crate::common::{Scratch, ok, run};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const DAY: i64 = 86_400;
const PORTAL: &str = "https://portal.example.gov/q?id=9%20UNION%20SELECT%209";
const OTHER: &str = "https://other.example/x?id=1%20UNION%20SELECT%201";

/// A timemap with one memento per capture time, on a non-Wayback archive.
fn timemap(original: &str, times: &[i64]) -> String {
    let mut t = format!("<{original}>; rel=\"original\",\n");
    for &ts in times {
        let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap();
        t.push_str(&format!(
            "<https://archive.example/{}/{original}>; rel=\"memento\"; datetime=\"{}\",\n",
            dt.format("%Y%m%d%H%M%S"),
            dt.format("%a, %d %b %Y %H:%M:%S GMT")
        ));
    }
    t
}

/// The fixture server: `/a/…` and `/a2/…` serve the portal timemap, `/b/…`
/// the other one, or holds the request open while `hang` is set (and says
/// so on `hit`).
struct Server {
    port: u16,
    hang: Arc<AtomicBool>,
    hit: mpsc::Receiver<()>,
}

fn serve(portal: String, other: String) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hang = Arc::new(AtomicBool::new(true));
    let (tx, hit) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let h = hang.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(conn) = conn else { continue };
            let (portal, other, h, tx) = (portal.clone(), other.clone(), h.clone(), tx.clone());
            std::thread::spawn(move || answer(conn, &portal, &other, &h, &tx));
        }
    });
    Server { port, hang, hit }
}

fn answer(
    mut c: TcpStream,
    portal: &str,
    other: &str,
    hang: &AtomicBool,
    hit: &Mutex<mpsc::Sender<()>>,
) {
    let mut req = Vec::new();
    let mut buf = [0u8; 1024];
    while !req.ends_with(b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    let req = String::from_utf8_lossy(&req);
    let path = req
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let body = if path.starts_with("/b/") {
        if hang.load(Ordering::SeqCst) {
            let _ = hit.lock().unwrap().send(());
            while hang.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            return;
        }
        other
    } else {
        portal
    };
    let _ = write!(
        c,
        "HTTP/1.1 200 OK\r\nContent-Type: application/link-format\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn watchlist(dir: &Path, port: u16, a_path: &str) {
    std::fs::write(
        dir.join("watchlist.toml"),
        format!(
            r#"min_interval_secs = 0
analysis_window_days = 30
retain_days = 400
http_cache_ttl_secs = 0

[[source]]
name = "tm-a"
kind = "memento"
pattern = "{PORTAL}"
endpoint = "http://127.0.0.1:{port}/{a_path}/"

[[source]]
name = "tm-b"
kind = "memento"
pattern = "{OTHER}"
endpoint = "http://127.0.0.1:{port}/b/"
"#
        ),
    )
    .unwrap();
}

fn latest(dir: &Path) -> std::path::PathBuf {
    let stamp = std::fs::read_to_string(dir.join("data/LATEST")).unwrap();
    dir.join("data/runs").join(stamp.trim())
}

fn json(p: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn an_interrupted_run_is_reported_by_the_next_and_old_captures_are_analysed() {
    let s = Scratch::new("watch-e2e");
    let d = s.path();
    let now = chrono::Utc::now().timestamp();
    let (recent, old) = (now - 2 * DAY, now - 60 * DAY);
    let srv = serve(
        timemap(PORTAL, &[recent, old]),
        timemap(OTHER, &[now - DAY]),
    );
    watchlist(d, srv.port, "a");

    // A case on the portal, whose indicators the new captures match.
    let case_records: String = (0..4)
        .map(|i| {
            format!(
                "{}\n",
                serde_json::json!({
                    "id": format!("c{i}"),
                    "ts": now - 90 * DAY + i * 40,
                    "url": format!("https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"),
                })
            )
        })
        .collect();
    std::fs::write(d.join("case.ndjson"), case_records).unwrap();
    ok(
        d,
        &[
            "case",
            "--data",
            "data",
            "new",
            "p-1",
            "--title",
            "Portal",
            "case.ndjson",
            "--record",
            "c0",
            "--record",
            "c1",
            "--record",
            "c2",
            "--record",
            "c3",
        ],
    );

    // Run 1 stores tm-a's captures, then is killed while tm-b hangs.
    let mut child = Command::new(env!("CARGO_BIN_EXE_swarmchase"))
        .args(["watch", "watchlist.toml", "--out", "data"])
        .current_dir(d)
        .env_remove("SWARMCHASE_DATA")
        .env_remove("URLQUERY_APIKEY")
        .env_remove("GITHUB_OUTPUT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    srv.hit.recv_timeout(Duration::from_secs(120)).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    srv.hang.store(false, Ordering::SeqCst);
    let state = json(&d.join("data/state.json"));
    let undigested = state["undigested"]["tm-a"].as_array().unwrap();
    assert_eq!(undigested.len(), 2, "{state}");
    assert!(!d.join("data/LATEST").exists(), "run 1 wrote no digest");

    // Run 2 reports run 1's records as new, with its own.
    let r = ok(d, &["watch", "watchlist.toml", "--out", "data"]);
    let run2 = latest(d);
    let digest = std::fs::read_to_string(run2.join("digest.md")).unwrap();
    let summary = json(&run2.join("run.json"));
    let counts = &summary["counts"];
    assert_eq!(counts["new_records"], 3, "{summary}\n{}", r.stderr);
    assert_eq!(counts["carried_over"], 2, "{summary}");
    assert_eq!(counts["new_before_window"], 1, "{summary}");
    assert!(
        digest.contains("2 record(s) stored by an earlier run that ended before its digest"),
        "{digest}"
    );
    assert!(
        digest.contains("1 new record(s) were captured before the 30-day analysis window"),
        "{digest}"
    );
    assert!(digest.contains("HTTP cache: "), "{digest}");
    let state = json(&d.join("data/state.json"));
    assert!(state.get("undigested").is_none(), "{state}");
    // The old capture was analysed, though it is outside the window.
    let analysis = std::fs::read_to_string(run2.join("analysis.json")).unwrap();
    let old_id = format!(
        "memento:archive.example:{}",
        chrono::DateTime::from_timestamp(old, 0)
            .unwrap()
            .format("%Y%m%d%H%M%S")
    );
    assert!(analysis.contains(&old_id), "{old_id} not analysed");

    // The digest's `case add` line works as written, old record included.
    let line = digest
        .lines()
        .find(|l| l.contains("`p-1`") && l.contains("case add"))
        .unwrap_or_else(|| panic!("no case add line in {digest}"));
    let cmd = line
        .split("Add them with `")
        .nth(1)
        .and_then(|t| t.split('`').next())
        .unwrap();
    assert!(cmd.contains(&old_id), "{cmd}");
    let args: Vec<&str> = cmd.split_whitespace().collect();
    assert_eq!(args[0], "swarmchase");
    let out = Command::new(env!("CARGO_BIN_EXE_swarmchase"))
        .args(&args[1..])
        .current_dir(d)
        .env("SWARMCHASE_DATA", d.join("data"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{cmd}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("added 2 record(s)"), "{stdout}");

    // A changed endpoint resets tm-a's position; what the store holds is
    // not reported again.
    watchlist(d, srv.port, "a2");
    ok(d, &["watch", "watchlist.toml", "--out", "data"]);
    let digest = std::fs::read_to_string(latest(d).join("digest.md")).unwrap();
    assert!(digest.contains("`tm-a`'s query changed"), "{digest}");
    assert_eq!(
        json(&latest(d).join("run.json"))["counts"]["new_records"],
        0
    );

    // `--only` pulls one source; `watch reset` starts one over.
    ok(
        d,
        &["watch", "watchlist.toml", "--out", "data", "--only", "tm-b"],
    );
    let sources = &json(&latest(d).join("run.json"))["health"]["sources"];
    assert_eq!(sources.as_array().unwrap().len(), 1, "{sources}");
    assert_eq!(sources[0]["name"], "tm-b");
    let r = run(
        d,
        &["watch", "watchlist.toml", "--out", "data", "--only", "nope"],
    );
    assert!(!r.ok && r.stderr.contains("no such source"), "{}", r.stderr);
    ok(d, &["watch", "reset", "tm-b", "--out", "data"]);
    let state = json(&d.join("data/state.json"));
    assert_eq!(state["sources"]["tm-b"]["cursor"], 0, "{state}");
    assert!(state["sources"]["tm-a"]["cursor"].as_i64().unwrap() > 0);
    assert_eq!(state["sources"]["tm-b"]["restart"], true, "{state}");
    // The run after a reset pulls tm-b from the start again, but what its
    // store already holds is neither stored twice nor reported as new.
    let store_b = d.join("data/store/tm-b.ndjson");
    let held = std::fs::read_to_string(&store_b).unwrap();
    ok(d, &["watch", "watchlist.toml", "--out", "data"]);
    let summary = json(&latest(d).join("run.json"));
    assert_eq!(summary["counts"]["new_records"], 0, "{summary}");
    assert_eq!(summary["leads"].as_array().map(Vec::len), Some(0));
    assert_eq!(std::fs::read_to_string(&store_b).unwrap(), held);
    let state = json(&d.join("data/state.json"));
    assert!(state["sources"]["tm-b"]["cursor"].as_i64().unwrap() > 0);
    assert!(state["sources"]["tm-b"].get("restart").is_none(), "{state}");
    let r = run(d, &["watch", "reset", "nope", "--out", "data"]);
    assert!(
        !r.ok && r.stderr.contains("no source `nope`"),
        "{}",
        r.stderr
    );
    // The cache prune command runs on its own too.
    let r = ok(
        d,
        &["watch", "prune-cache", "watchlist.toml", "--out", "data"],
    );
    assert!(r.stdout.contains("deleted 0 entries"), "{}", r.stdout);
}
