//! A local registry for Cargo's sparse protocol: the files under one folder, served over HTTP on
//! 127.0.0.1 for GET requests, one connection at a time.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// Where Cargo downloads packages from, as the index's config.json names it.
pub(crate) const DOWNLOADS: &str = "/dl/";

/// A running registry and the number of package downloads Cargo asked it for.
pub(crate) struct Registry {
    port: u16,
    downloads: Arc<AtomicUsize>,
}

impl Registry {
    /// Serves `root` on a free port, from a thread that ends with the process.
    pub(crate) fn start(root: PathBuf) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let downloads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&downloads);
        thread::spawn(move || {
            for stream in listener.incoming() {
                // A failed answer leaves Cargo without its file, and Cargo's own error then stops
                // the harness; the cause is printed here.
                if let Err(error) = stream.and_then(|stream| answer(&stream, &root, &counter)) {
                    eprintln!("registry: {error}");
                }
            }
        });
        Ok(Self { port, downloads })
    }

    /// The registry's address, for the index's config.json and Cargo's configuration.
    pub(crate) fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub(crate) fn downloads(&self) -> usize {
        self.downloads.load(Ordering::SeqCst)
    }
}

/// Answers one request with the file it names, or 404. No Last-Modified or ETag header is sent,
/// so Cargo never revalidates and every answer carries the file as it is now; the shell version
/// waited two seconds instead, so that its server's Last-Modified changed.
fn answer(stream: &TcpStream, root: &Path, downloads: &AtomicUsize) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    // The headers are read to their end, so that closing the connection does not reset it.
    let mut header = String::new();
    while reader.read_line(&mut header)? > 0 && !header.trim().is_empty() {
        header.clear();
    }
    let mut words = request.split_whitespace();
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    if method == "GET" && target.starts_with(DOWNLOADS) {
        downloads.fetch_add(1, Ordering::SeqCst);
    }
    // Only files under `root`: a path that climbs out of it is not served.
    let file = target
        .strip_prefix('/')
        .filter(|path| method == "GET" && !path.contains(".."));
    let body = match file.map(|path| fs::read(root.join(path))) {
        Some(Ok(body)) => Some(body),
        Some(Err(error)) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => None,
    };
    let mut stream = stream;
    match body {
        Some(body) => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(&body)?;
        }
        None => stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?,
    }
    stream.flush()
}
