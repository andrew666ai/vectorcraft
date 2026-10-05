//! Where MCP tool calls end up: a control-channel method call.

use std::io::{BufRead, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::control_auth::{AUTH_METHOD, LineRead, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_bounded_line, require_loopback, validate_token};

/// Something that answers control-channel methods (`engine.execute`, `document.inspect`,
/// `ui.pointer`, `ui.render`, `app.export`, …). See `vectorcraft_ui_egui::control` for the list.
pub trait Backend {
    /// Call one method. `Ok` carries the `result`, `Err` the error message.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
    /// True when a real UI is attached (`ui.*` methods like `ui.key` / `ui.inspect` work).
    fn has_ui(&self) -> bool;
    /// Short human description ("headless", "remote 127.0.0.1:7979"). Never includes the token.
    fn describe(&self) -> String;
}

/// A running VectorCraft app, reached through its loopback control port.
/// Debug output names the address and omits the bearer token.
pub struct Remote {
    addr: String,
    token: String,
    conn: Option<(std::io::BufReader<TcpStream>, TcpStream)>,
    next_id: u64,
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Remote").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl Remote {
    /// Connect to a loopback `addr` (e.g. `127.0.0.1:7979`) and authenticate.
    /// `token` is 64 hexadecimal characters. It is not logged.
    pub fn connect(addr: &str, token: &str) -> std::io::Result<Self> {
        validate_token(token).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        require_loopback(addr)?;
        let mut remote = Self { addr: addr.to_string(), token: token.to_ascii_lowercase(), conn: None, next_id: 1 };
        remote.reconnect()?;
        Ok(remote)
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    fn reconnect(&mut self) -> std::io::Result<()> {
        self.conn = None;
        require_loopback(&self.addr)?;
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("cannot resolve {}", self.addr));
        for sa in self.addr.to_socket_addrs()? {
            if !sa.ip().is_loopback() {
                last = std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("control address must be loopback, got {sa}"));
                continue;
            }
            match TcpStream::connect_timeout(&sa, Duration::from_millis(800)) {
                Ok(mut stream) => {
                    stream.set_nodelay(true).ok();
                    // The app answers within 60 s (its own timeout); leave headroom.
                    stream.set_read_timeout(Some(Duration::from_secs(90))).ok();
                    let read = stream.try_clone()?;
                    let mut reader = std::io::BufReader::new(read);
                    let id = self.next_id;
                    self.next_id = self.next_id.saturating_add(1);
                    authenticate(&mut reader, &mut stream, &self.token, id)?;
                    self.conn = Some((reader, stream));
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn roundtrip(&mut self, line: &str) -> std::io::Result<String> {
        if line.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("request exceeds {MAX_REQUEST_BYTES} bytes")));
        }
        self.roundtrip_once(line, true)
    }

    fn roundtrip_once(&mut self, line: &str, retry: bool) -> std::io::Result<String> {
        if self.conn.is_none() {
            self.reconnect()?;
        }
        let Some((reader, writer)) = self.conn.as_mut() else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected to the app"));
        };
        if let Err(e) = write_line(writer, line) {
            self.conn = None;
            return if retry { self.roundtrip_once(line, false) } else { Err(e) };
        }
        let mut reply = String::new();
        match read_bounded_line(reader, &mut reply, MAX_RESPONSE_BYTES) {
            Ok(LineRead::Line) => Ok(reply),
            Ok(LineRead::Eof) => {
                self.conn = None;
                if retry {
                    self.roundtrip_once(line, false)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "control channel closed"))
                }
            }
            // The app may already have applied the method. Do not send it again.
            Ok(LineRead::TooLong) => {
                self.conn = None;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bridge response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
                ))
            }
            Err(e) => {
                self.conn = None;
                if retry { self.roundtrip_once(line, false) } else { Err(e) }
            }
        }
    }
}

fn write_line(writer: &mut TcpStream, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn authenticate(reader: &mut impl BufRead, writer: &mut TcpStream, token: &str, id: u64) -> std::io::Result<()> {
    let line = json!({"id": id, "method": AUTH_METHOD, "params": {"token": token}}).to_string();
    write_line(writer, &line)?;
    let mut reply = String::new();
    match read_bounded_line(reader, &mut reply, MAX_RESPONSE_BYTES)? {
        LineRead::Line => {}
        LineRead::Eof => {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "control channel closed before authentication"));
        }
        LineRead::TooLong => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "authentication reply exceeds the response budget"));
        }
    }
    let v: Value =
        serde_json::from_str(reply.trim()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad authentication reply"))?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "authentication required"))
    }
}

impl Backend for Remote {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let line = json!({"id": id, "method": method, "params": params}).to_string();
        // `roundtrip` reconnects and authenticates once if the socket died.
        // An oversized reply is not retried: the app may already have applied it.
        let reply = self.roundtrip(&line).map_err(|e| {
            self.conn = None;
            if e.kind() == std::io::ErrorKind::InvalidData {
                e.to_string()
            } else {
                format!("VectorCraft app at {} is not reachable: {e}", self.addr)
            }
        })?;
        let v: Value = serde_json::from_str(reply.trim()).map_err(|_| "bad reply from app".to_string())?;
        if v.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(v.get("error").and_then(Value::as_str).unwrap_or("unknown error").to_string())
        }
    }

    fn has_ui(&self) -> bool {
        true
    }

    fn describe(&self) -> String {
        format!("remote {}", self.addr)
    }
}
