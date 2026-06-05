//! Servidor de detecção de fraude. mmap do índice + busca IVF.
//! HTTP/1.1 mínimo, feito à mão, com TCP_NODELAY (evita atraso de Nagle nas
//! respostas pequenas) e uma thread por conexão keep-alive (sem fila/mutex).
//! Endpoints: GET /ready, POST /fraud-score.

use memmap2::Mmap;
use rinha_fraud::index::Index;
use rinha_fraud::vectorize::{quantize, vectorize, Request};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn main() {
    let index_path = std::env::var("INDEX_PATH").unwrap_or_else(|_| "index.bin".into());
    let nprobe = env_usize("NPROBE", 24);
    let port = env_usize("PORT", 9999);

    // mmap do índice; vaza para 'static (vive por todo o processo, read-only).
    let file = std::fs::File::open(&index_path)
        .unwrap_or_else(|e| panic!("abrir índice {index_path}: {e}"));
    let mmap = unsafe { Mmap::map(&file).expect("mmap índice") };
    let bytes: &'static [u8] = Box::leak(Box::new(mmap));
    let index: &'static Index<'static> = Box::leak(Box::new(Index::from_bytes(bytes)));

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!(
        "[server] {} vetores, {} clusters, nprobe={nprobe}, escutando tcp:{addr}",
        index.num_vectors, index.num_clusters
    );

    // Uma thread por conexão. O nginx mantém um pool keep-alive limitado, então
    // o número de threads fica baixo. Sem fila compartilhada -> sem contenção.
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = stream.set_nodelay(true); // crítico: desliga o Nagle
            std::thread::spawn(move || handle_conn(stream, index, nprobe));
        }
    }
}

fn handle_conn(stream: TcpStream, index: &'static Index<'static>, nprobe: usize) {
    let write_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::with_capacity(8192, stream);
    let mut writer = write_stream;
    let mut line = String::with_capacity(256);
    let mut body = Vec::with_capacity(1024);
    let mut out = Vec::with_capacity(256);

    loop {
        // ---- linha de requisição (ex.: "POST /fraud-score HTTP/1.1") ----
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return, // conexão fechada
            _ => {}
        }
        let is_post = line.as_bytes().first() == Some(&b'P');

        // ---- headers: só precisamos do Content-Length ----
        let mut content_len = 0usize;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                _ => {}
            }
            let t = line.trim_end();
            if t.is_empty() {
                break; // fim dos headers
            }
            if let Some(idx) = t.find(':') {
                if t[..idx].eq_ignore_ascii_case("content-length") {
                    content_len = t[idx + 1..].trim().parse().unwrap_or(0);
                }
            }
        }

        // ---- corpo (apenas POST) ----
        let resp_body: &str = if is_post {
            body.clear();
            body.resize(content_len, 0);
            if reader.read_exact(&mut body).is_err() {
                return;
            }
            match score(&body, index, nprobe) {
                Some((approved, fs)) => {
                    fmt_into(&mut out, approved, fs);
                    // SAFETY: fmt_into só escreve ASCII.
                    unsafe { std::str::from_utf8_unchecked(&out) }
                }
                None => "{\"approved\":true,\"fraud_score\":0.0}",
            }
        } else {
            "ok" // GET /ready
        };

        // ---- resposta ----
        if write_response(&mut writer, resp_body).is_err() {
            return;
        }
    }
}

#[inline]
fn write_response(w: &mut TcpStream, body: &str) -> std::io::Result<()> {
    // Uma única escrita (com NODELAY, sai no fio imediatamente).
    let mut buf = Vec::with_capacity(128 + body.len());
    buf.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ");
    let mut n = [0u8; 20];
    buf.extend_from_slice(itoa(body.len(), &mut n));
    buf.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    buf.extend_from_slice(body.as_bytes());
    w.write_all(&buf)
}

#[inline]
fn itoa(mut v: usize, buf: &mut [u8; 20]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

#[inline]
fn score(body: &[u8], index: &Index, nprobe: usize) -> Option<(bool, f32)> {
    let req: Request = serde_json::from_slice(body).ok()?;
    let v = vectorize(&req);
    let q = quantize(&v);
    let fs = index.fraud_score(&v, &q, nprobe);
    Some((fs < 0.6, fs))
}

/// Escreve `{"approved":<bool>,"fraud_score":<x.x>}` em `out` (múltiplo de 0.2).
#[inline]
fn fmt_into(out: &mut Vec<u8>, approved: bool, fraud_score: f32) {
    out.clear();
    out.extend_from_slice(b"{\"approved\":");
    out.extend_from_slice(if approved { b"true" } else { b"false" });
    out.extend_from_slice(b",\"fraud_score\":");
    // fraud_score sempre é k/5 -> uma casa decimal.
    let tenths = (fraud_score * 10.0).round() as i32; // 0,2,4,6,8,10
    out.push(b'0' + (tenths / 10) as u8);
    out.push(b'.');
    out.push(b'0' + (tenths % 10) as u8);
    out.push(b'}');
}
