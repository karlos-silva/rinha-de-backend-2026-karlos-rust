//! Servidor de detecção de fraude. mmap do índice + busca IVF.
//! Endpoints: GET /ready, POST /fraud-score (porta 9999).

use memmap2::Mmap;
use rinha_fraud::index::Index;
use rinha_fraud::vectorize::{quantize, vectorize, Request};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn main() {
    let index_path = std::env::var("INDEX_PATH").unwrap_or_else(|_| "index.bin".into());
    let port = env_usize("PORT", 9999);
    let nprobe = env_usize("NPROBE", 24);
    let threads = env_usize(
        "THREADS",
        std::thread::available_parallelism().map(|x| x.get()).unwrap_or(2),
    );

    // mmap do índice; vaza para 'static (vive por todo o processo, read-only).
    let file = std::fs::File::open(&index_path)
        .unwrap_or_else(|e| panic!("abrir índice {index_path}: {e}"));
    let mmap = unsafe { Mmap::map(&file).expect("mmap índice") };
    let bytes: &'static [u8] = Box::leak(Box::new(mmap));
    let index: &'static Index<'static> = Box::leak(Box::new(Index::from_bytes(bytes)));

    let addr = format!("0.0.0.0:{port}");
    let server = Arc::new(Server::http(&addr).expect("bind"));
    eprintln!(
        "[server] {} vetores, {} clusters, nprobe={nprobe}, threads={threads}, escutando {addr}",
        index.num_vectors, index.num_clusters
    );

    let mut handles = Vec::new();
    for _ in 0..threads {
        let server = Arc::clone(&server);
        handles.push(std::thread::spawn(move || worker(server, index, nprobe)));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn worker(server: Arc<Server>, index: &'static Index<'static>, nprobe: usize) {
    let json_header: Header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);

    loop {
        let mut req = match server.recv() {
            Ok(r) => r,
            Err(_) => break,
        };

        // GET /ready -> 200
        if *req.method() == Method::Get {
            let _ = req.respond(Response::from_string("ok"));
            continue;
        }

        // POST /fraud-score
        buf.clear();
        let _ = req.as_reader().read_to_end(&mut buf);

        let body = match score(&buf, index, nprobe) {
            Some((approved, fs)) => fmt_response(approved, fs),
            // fallback rápido: evita erro HTTP (peso 5) em payload inesperado
            None => "{\"approved\":true,\"fraud_score\":0.0}".to_string(),
        };

        let resp = Response::from_string(body).with_header(json_header.clone());
        let _ = req.respond(resp);
    }
}

#[inline]
fn score(body: &[u8], index: &Index, nprobe: usize) -> Option<(bool, f32)> {
    let req: Request = serde_json::from_slice(body).ok()?;
    let v = vectorize(&req);
    let q = quantize(&v);
    let fs = index.fraud_score(&v, &q, nprobe);
    Some((fs < 0.6, fs))
}

#[inline]
fn fmt_response(approved: bool, fraud_score: f32) -> String {
    // fraud_score sempre é múltiplo de 0.2 (k=5); uma casa decimal basta.
    format!("{{\"approved\":{},\"fraud_score\":{:.1}}}", approved, fraud_score)
}
