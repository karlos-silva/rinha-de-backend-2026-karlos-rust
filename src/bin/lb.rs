//! Load balancer puro: proxy TCP (porta 9999) -> unix sockets das APIs,
//! round-robin por conexão. Encaminha bytes crus, sem inspecionar o payload
//! nem aplicar lógica (respeita a regra do LB).
//!
//! Env: PORT (default 9999), SOCKETS="/sockets/api1.sock,/sockets/api2.sock".

use std::io::copy;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(9999);
    let sockets: Arc<Vec<String>> = Arc::new(
        std::env::var("SOCKETS")
            .expect("SOCKETS")
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
    );

    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind 9999");
    eprintln!("[lb] escutando :{port} -> {:?}", sockets);

    let rr = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(client) = conn else { continue };
        let _ = client.set_nodelay(true);
        let idx = rr.fetch_add(1, Ordering::Relaxed) % sockets.len();
        let sock = sockets[idx].clone();
        std::thread::spawn(move || proxy(client, &sock));
    }
}

fn connect_retry(sock: &str) -> Option<UnixStream> {
    // O socket pode não existir ainda no startup das APIs; tenta por alguns segundos.
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(sock) {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn proxy(client: TcpStream, sock: &str) {
    let Some(backend) = connect_retry(sock) else { return };

    let (mut c_read, mut c_write) = (client.try_clone().unwrap(), client);
    let (mut b_read, mut b_write) = (backend.try_clone().unwrap(), backend);

    // client -> backend
    let up = std::thread::spawn(move || {
        let _ = copy(&mut c_read, &mut b_write);
        let _ = b_write.shutdown(std::net::Shutdown::Write);
    });
    // backend -> client
    let _ = copy(&mut b_read, &mut c_write);
    let _ = c_write.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}
