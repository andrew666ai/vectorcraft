//! Bearer token and size limits for the loopback control channel.
//!
//! Personal, same-machine use: one shared token, no per-tool capabilities.
//! The token never belongs in a log line or a reply.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

/// First request on a TCP control connection. Nothing else is dispatched before it succeeds.
pub const AUTH_METHOD: &str = "auth";
/// Encoded JSON request line, including its newline.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Encoded JSON reply, including its newline.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Accepted TCP connections at once, per listener.
pub const MAX_CONNECTIONS: usize = 16;
/// JSON-RPC array messages on stdio MCP.
pub const MAX_BATCH_STEPS: usize = 256;
/// Idle read and write timeout on a control socket.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// One framed read from a control or stdio stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Read one line, and never keep more than `maximum + 1` bytes of it.
pub fn read_bounded_line(reader: &mut impl BufRead, line: &mut String, maximum: usize) -> std::io::Result<LineRead> {
    line.clear();
    let mut limited = std::io::Read::take(reader, (maximum as u64).saturating_add(1));
    let n = limited.read_line(line)?;
    if n == 0 {
        Ok(LineRead::Eof)
    } else if n > maximum {
        Ok(LineRead::TooLong)
    } else {
        Ok(LineRead::Line)
    }
}

/// 256-bit token as 64 hexadecimal characters, from the OS CSPRNG.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| format!("cannot generate control token: {e}"))?;
    let mut token = String::with_capacity(TOKEN_HEX_LEN);
    for byte in bytes {
        token.push(hex_digit(byte >> 4));
        token.push(hex_digit(byte & 0x0f));
    }
    Ok(token)
}

fn hex_digit(n: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match HEX.get(usize::from(n)) {
        Some(c) => char::from(*c),
        None => '0',
    }
}

/// The form [`generate_token`] emits. Uppercase hex is accepted and stored lowercase.
pub fn validate_token(token: &str) -> Result<(), String> {
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("control token must contain exactly 64 hexadecimal characters".into());
    }
    Ok(())
}

/// Compare fixed-width tokens without returning on the first differing byte.
pub fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != TOKEN_HEX_LEN || supplied.len() != TOKEN_HEX_LEN {
        return false;
    }
    let expected = expected.as_bytes();
    let supplied = supplied.as_bytes();
    let mut different = 0u8;
    for i in 0..TOKEN_HEX_LEN {
        let a = expected.get(i).copied().unwrap_or(0);
        let b = supplied.get(i).copied().unwrap_or(0);
        different |= a ^ b;
    }
    different == 0
}

/// Check the first TCP frame. The reply never contains the token.
pub fn authentication_reply(line: &str, expected_token: &str) -> (Value, bool) {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return (json!({"id": null, "ok": false, "error": "authentication required"}), false),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let supplied = req.get("params").and_then(|p| p.get("token")).and_then(Value::as_str).unwrap_or("");
    let expected = expected_token.to_ascii_lowercase();
    let ok = req.get("method").and_then(Value::as_str) == Some(AUTH_METHOD) && token_matches(&expected, &supplied.to_ascii_lowercase());
    if ok {
        (json!({"id": id, "ok": true, "result": {"authenticated": true}}), true)
    } else {
        (json!({"id": id, "ok": false, "error": "authentication required"}), false)
    }
}

/// `127.0.0.1:7979` and `localhost` are accepted. Anything else is refused before connect.
pub fn require_loopback(addr: &str) -> std::io::Result<()> {
    let mut saw = false;
    for sa in addr.to_socket_addrs()? {
        saw = true;
        if !sa.ip().is_loopback() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("control address must be loopback, got {sa}")));
        }
    }
    if !saw {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("cannot resolve {addr}")));
    }
    Ok(())
}

fn read_token_file(path: &Path) -> Result<String, TokenError> {
    let token = std::fs::read_to_string(path).map_err(|e| TokenError::Io(format!("{}: {e}", path.display())))?;
    let token = token.trim().to_owned();
    validate_token(&token).map_err(TokenError::Bad)?;
    Ok(token.to_ascii_lowercase())
}

fn create_token_file(path: &Path, token: &str) -> Result<(), TokenError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| TokenError::Io(format!("{}: {e}", parent.display())))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| TokenError::Io(format!("{}: {e}", path.display())))?;
    if let Err(e) = writeln!(file, "{token}") {
        drop(file);
        // A half-written file would fail the next start; drop it.
        let _ = std::fs::remove_file(path);
        return Err(TokenError::Io(format!("{}: {e}", path.display())));
    }
    Ok(())
}

enum TokenError {
    Io(String),
    Bad(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Io(s) | TokenError::Bad(s) => f.write_str(s),
        }
    }
}

/// Server credential. A missing token file is created; an existing one is read.
/// Pass a token or a file, not both. With neither, the caller should supply the default path.
pub fn server_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, String> {
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let Some(path) = token_file else {
        return Err("control auth needs a token or a token file".into());
    };
    match read_token_file(path) {
        Ok(existing) => Ok(existing),
        Err(TokenError::Io(_)) if !path.exists() => {
            let token = generate_token()?;
            match create_token_file(path, &token) {
                Ok(()) => Ok(token),
                Err(TokenError::Io(_)) if path.exists() => read_token_file(path).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Client credential. Clients never create a token.
pub fn client_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, String> {
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let Some(path) = token_file else {
        return Err(
            "control connection needs --control-token, --control-token-file, VECTORCRAFT_CONTROL_TOKEN, or VECTORCRAFT_CONTROL_TOKEN_FILE".into()
        );
    };
    read_token_file(path).map_err(|e| e.to_string())
}

/// Flag or env. The explicit argument wins over the environment variable.
pub fn token_inputs(supplied: Option<String>, token_file: Option<PathBuf>) -> (Option<String>, Option<PathBuf>) {
    let supplied = supplied.filter(|s| !s.is_empty()).or_else(|| std::env::var("VECTORCRAFT_CONTROL_TOKEN").ok().filter(|s| !s.is_empty()));
    let token_file = token_file.or_else(|| std::env::var_os("VECTORCRAFT_CONTROL_TOKEN_FILE").map(PathBuf::from));
    (supplied, token_file)
}

/// `control-token` beside the UI preferences. The file is the secret; this path is not.
pub fn default_token_path() -> Option<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/VectorCraft"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("VectorCraft"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|c| c.join("vectorcraft"))
    };
    base.map(|b| b.join("control-token"))
}

/// Token the desktop listener will require, and the file path to print (never the token).
pub fn resolve_server_token(supplied: Option<String>, token_file: Option<PathBuf>) -> Result<(String, Option<PathBuf>), String> {
    let (supplied, mut token_file) = token_inputs(supplied, token_file);
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if supplied.is_none() && token_file.is_none() {
        if std::env::var_os("VECTORCRAFT_NO_PREFS").is_some() {
            return Err(
                "control auth needs --control-token, --control-token-file, VECTORCRAFT_CONTROL_TOKEN, or VECTORCRAFT_CONTROL_TOKEN_FILE".into()
            );
        }
        token_file = default_token_path();
        if token_file.is_none() {
            return Err("no home directory for the control token file; pass --control-token-file".into());
        }
    }
    let token = server_token(supplied.as_deref(), token_file.as_deref())?;
    Ok((token, token_file))
}

/// Token the MCP bridge sends. A default token file is used only when it already exists.
pub fn resolve_client_token(supplied: Option<String>, token_file: Option<PathBuf>) -> Result<String, String> {
    let (supplied, mut token_file) = token_inputs(supplied, token_file);
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if supplied.is_none() && token_file.is_none() {
        token_file = default_token_path().filter(|p| p.is_file());
    }
    client_token(supplied.as_deref(), token_file.as_deref())
}

/// Counts active connections and hands out a permit only while under the cap.
pub struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), max })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(actual) => current = actual,
            }
        }
    }
}

pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Nodelay plus idle timeouts, before a connection is served.
pub fn configure_stream(stream: &std::net::TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("response exceeds {} bytes", self.maximum)));
        }
        self.bytes.try_reserve(buf.len()).map_err(|error| std::io::Error::other(format!("response allocation failed: {error}")))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_with_limit(value: &Value, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut writer = LimitedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.bytes)
}

/// Write one JSON line. A reply that does not fit is replaced by a short error that keeps `id`.
pub fn write_reply(out: &mut impl Write, reply: &Value) -> std::io::Result<()> {
    let encoded = match encode_with_limit(reply, MAX_RESPONSE_BYTES.saturating_sub(1)) {
        Ok(bytes) => bytes,
        Err(()) => {
            let error = json!({
                "id": reply.get("id").cloned().unwrap_or(Value::Null),
                "ok": false,
                "error": format!("response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
            });
            match encode_with_limit(&error, MAX_RESPONSE_BYTES.saturating_sub(1)) {
                Ok(bytes) => bytes,
                Err(()) => b"{\"id\":null,\"ok\":false,\"error\":\"response budget exceeded\"}".to_vec(),
            }
        }
    };
    out.write_all(&encoded)?;
    out.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_valid_and_distinct() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        validate_token(&a).unwrap();
        assert_ne!(a, b);
        assert!(token_matches(&a, &a));
        assert!(!token_matches(&a, &b));
        assert!(!token_matches(&a, "short"));
    }

    #[test]
    fn bounded_reader_reads_successive_lines() {
        let mut reader = std::io::Cursor::new("one\ntwo\n");
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line, 100).unwrap(), LineRead::Line);
        assert_eq!(line, "one\n");
        assert_eq!(read_bounded_line(&mut reader, &mut line, 100).unwrap(), LineRead::Line);
        assert_eq!(line, "two\n");
        assert_eq!(read_bounded_line(&mut reader, &mut line, 100).unwrap(), LineRead::Eof);
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 1));
        let mut reader = std::io::Cursor::new(input);
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line, MAX_REQUEST_BYTES).unwrap(), LineRead::TooLong);
    }

    #[test]
    fn unauthenticated_and_wrong_token_are_rejected_without_echoing_the_secret() {
        let token = generate_token().unwrap();
        let (reply, authenticated) = authentication_reply(r#"{"id":1,"method":"ui.inspect","params":{}}"#, &token);
        assert!(!authenticated);
        assert_eq!(reply["error"], "authentication required");
        assert!(reply.get("result").is_none());
        assert!(!reply.to_string().contains(&token));

        let wrong = "00".repeat(32);
        let line = json!({"id": 2, "method": AUTH_METHOD, "params": {"token": wrong}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(!authenticated);
        assert_eq!(reply["error"], "authentication required");
        assert!(!reply.to_string().contains(&token));
        assert!(!reply.to_string().contains(&wrong));

        // A real token on some other method is still not a session.
        let line = json!({"id": 3, "method": "engine.execute", "params": {"token": token}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(!authenticated);
        assert!(!reply.to_string().contains(&token));
    }

    #[test]
    fn matching_token_authenticates() {
        let token = generate_token().unwrap();
        let line = json!({"id": 2, "method": AUTH_METHOD, "params": {"token": token}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(authenticated);
        assert_eq!(reply["result"]["authenticated"], true);
        assert!(!reply.to_string().contains(&token));
    }

    #[test]
    fn token_file_round_trips_and_is_private() {
        let path = std::env::temp_dir().join(format!("vectorcraft-control-token-{}-{}.txt", std::process::id(), generate_token().unwrap()));
        let server = server_token(None, Some(&path)).unwrap();
        let client = client_token(None, Some(&path)).unwrap();
        assert_eq!(server, client);
        assert!(token_matches(&server, &client));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn oversized_reply_is_one_error_line_and_keeps_the_id() {
        let reply = json!({"id": 7, "ok": true, "result": "x".repeat(MAX_RESPONSE_BYTES)});
        let mut out = Vec::new();
        write_reply(&mut out, &reply).unwrap();
        assert!(out.len() < 1024);
        assert_eq!(out.iter().filter(|&&byte| byte == b'\n').count(), 1);
        let error: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(error["id"], 7);
        assert_eq!(error["ok"], false);
        assert!(error["error"].as_str().unwrap().contains("operation may have completed"));
    }

    #[test]
    fn loopback_addresses_only() {
        require_loopback("127.0.0.1:9").unwrap();
        let err = require_loopback("203.0.113.5:9").unwrap_err();
        assert!(err.to_string().contains("loopback"));
        let err = require_loopback("0.0.0.0:9").unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }
}
