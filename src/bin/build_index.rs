//! Pré-processa references.json.gz num blob binário mmap-ável.
//!
//! Uso: build_index <references.json.gz> <out.bin> [num_clusters]
//!
//! Passos: descomprime -> parse manual rápido -> k-means (IVF) ->
//! reordena vetores por cluster -> quantiza i16 -> grava blob.

use flate2::read::MultiGzDecoder;
use rinha_fraud::consts::{DIM, PAD, SCALE};
use rinha_fraud::index::MAGIC;
use std::io::{Read, Write};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let in_path = args.get(1).map(String::as_str).unwrap_or("references.json.gz");
    let out_path = args.get(2).map(String::as_str).unwrap_or("index.bin");
    let num_clusters: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2048);

    let t0 = Instant::now();
    eprintln!("[build] descomprimindo {in_path} ...");
    let raw = decompress(in_path);
    eprintln!("[build] {} bytes descomprimidos em {:?}", raw.len(), t0.elapsed());

    let t1 = Instant::now();
    let (vectors, labels) = parse_refs(&raw);
    drop(raw);
    let n = vectors.len();
    eprintln!("[build] {n} vetores parseados em {:?}", t1.elapsed());

    let t2 = Instant::now();
    let centroids = kmeans(&vectors, num_clusters, 12);
    eprintln!("[build] k-means ({num_clusters} clusters) em {:?}", t2.elapsed());

    let t3 = Instant::now();
    let assign = assign_all(&vectors, &centroids, num_clusters);
    eprintln!("[build] atribuição final em {:?}", t3.elapsed());

    // Offsets (prefix sum) e ordem por cluster.
    let mut counts = vec![0u32; num_clusters];
    for &a in &assign {
        counts[a as usize] += 1;
    }
    let mut offsets = vec![0u32; num_clusters + 1];
    for c in 0..num_clusters {
        offsets[c + 1] = offsets[c] + counts[c];
    }
    // Posição de escrita por cluster (cópia mutável dos offsets).
    let mut cursor: Vec<u32> = offsets[..num_clusters].to_vec();

    // Vetores quantizados i16 reordenados + labels reordenados (bitset).
    let mut q_vectors = vec![0i16; n * PAD];
    let mut out_labels = vec![0u8; n.div_ceil(8)];
    for i in 0..n {
        let c = assign[i] as usize;
        let dst = cursor[c] as usize;
        cursor[c] += 1;
        let v = &vectors[i];
        let base = dst * PAD;
        for k in 0..DIM {
            q_vectors[base + k] = (v[k] * SCALE).round() as i16;
        }
        if labels[i] {
            out_labels[dst >> 3] |= 1 << (dst & 7);
        }
    }

    let t4 = Instant::now();
    write_blob(out_path, n, num_clusters, &centroids, &offsets, &q_vectors, &out_labels);
    eprintln!("[build] blob gravado em {:?}", t4.elapsed());
    eprintln!("[build] TOTAL {:?}", t0.elapsed());
}

fn decompress(path: &str) -> Vec<u8> {
    let f = std::fs::File::open(path).expect("abrir gz");
    let mut dec = MultiGzDecoder::new(f);
    let mut buf = Vec::with_capacity(300 << 20);
    dec.read_to_end(&mut buf).expect("descomprimir");
    buf
}

/// Parser manual do array `[{"vector":[...14...],"label":"legit|fraud"}, ...]`.
fn parse_refs(data: &[u8]) -> (Vec<[f32; DIM]>, Vec<bool>) {
    let n = data.len();
    let mut vectors: Vec<[f32; DIM]> = Vec::with_capacity(3_000_000);
    let mut labels: Vec<bool> = Vec::with_capacity(3_000_000);

    let mut i = 0usize;
    // pula até o '[' externo
    while i < n && data[i] != b'[' {
        i += 1;
    }
    i += 1;

    loop {
        // pula whitespace, vírgulas e as chaves de abertura/fecho dos objetos
        while i < n && matches!(data[i], b' ' | b'\n' | b'\r' | b'\t' | b',' | b'{' | b'}') {
            i += 1;
        }
        if i >= n || data[i] == b']' {
            break;
        }
        // acha o '[' do vetor
        while i < n && data[i] != b'[' {
            i += 1;
        }
        i += 1; // passa o '['

        let mut v = [0f32; DIM];
        for slot in v.iter_mut() {
            while i < n && matches!(data[i], b' ' | b'\n' | b'\r' | b'\t' | b',') {
                i += 1;
            }
            let start = i;
            while i < n && !matches!(data[i], b',' | b']' | b' ' | b'\n' | b'\r' | b'\t') {
                i += 1;
            }
            *slot = parse_f32(&data[start..i]);
        }
        // avança até ']' do vetor
        while i < n && data[i] != b']' {
            i += 1;
        }
        i += 1;

        // acha o ':' do label, depois a primeira aspa de abertura do valor
        while i < n && data[i] != b':' {
            i += 1;
        }
        i += 1;
        while i < n && data[i] != b'"' {
            i += 1;
        }
        i += 1;
        let lstart = i;
        while i < n && data[i] != b'"' {
            i += 1;
        }
        let is_fraud = &data[lstart..i] == b"fraud";
        i += 1;

        vectors.push(v);
        labels.push(is_fraud);
    }

    (vectors, labels)
}

#[inline]
fn parse_f32(b: &[u8]) -> f32 {
    // SAFETY: o dataset é ASCII numérico bem-formado.
    unsafe { std::str::from_utf8_unchecked(b) }.parse().unwrap()
}

// ---------- k-means ----------

struct Rng(u64);
impl Rng {
    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[inline]
fn dist2(a: &[f32; DIM], c: &[f32]) -> f32 {
    let mut d = 0.0f32;
    for k in 0..DIM {
        let x = a[k] - c[k];
        d += x * x;
    }
    d
}

#[inline]
fn nearest(point: &[f32; DIM], centroids: &[f32], k: usize) -> (usize, f32) {
    let mut best = 0usize;
    let mut bd = f32::INFINITY;
    for c in 0..k {
        let d = dist2(point, &centroids[c * DIM..c * DIM + DIM]);
        if d < bd {
            bd = d;
            best = c;
        }
    }
    (best, bd)
}

/// Treina centróides via Lloyd em uma amostra (rápido) e retorna `k*DIM` f32.
fn kmeans(vectors: &[[f32; DIM]], k: usize, iters: usize) -> Vec<f32> {
    let n = vectors.len();
    let mut rng = Rng(0x9E3779B97F4A7C15);

    // amostra de treino (limita custo do Lloyd)
    let sample_size = (n).min(300_000);
    let mut sample: Vec<usize> = Vec::with_capacity(sample_size);
    for _ in 0..sample_size {
        sample.push((rng.next() as usize) % n);
    }

    // init: k pontos distintos da amostra
    let mut centroids = vec![0f32; k * DIM];
    for c in 0..k {
        let idx = sample[(rng.next() as usize) % sample.len()];
        centroids[c * DIM..c * DIM + DIM].copy_from_slice(&vectors[idx]);
    }

    let mut sums = vec![0f32; k * DIM];
    let mut counts = vec![0u32; k];
    for _it in 0..iters {
        sums.iter_mut().for_each(|x| *x = 0.0);
        counts.iter_mut().for_each(|x| *x = 0);
        for &si in &sample {
            let p = &vectors[si];
            let (c, _) = nearest(p, &centroids, k);
            counts[c] += 1;
            let base = c * DIM;
            for d in 0..DIM {
                sums[base + d] += p[d];
            }
        }
        for c in 0..k {
            if counts[c] > 0 {
                let inv = 1.0 / counts[c] as f32;
                for d in 0..DIM {
                    centroids[c * DIM + d] = sums[c * DIM + d] * inv;
                }
            } else {
                // cluster vazio: reinicia num ponto aleatório
                let idx = sample[(rng.next() as usize) % sample.len()];
                centroids[c * DIM..c * DIM + DIM].copy_from_slice(&vectors[idx]);
            }
        }
    }
    centroids
}

/// Atribui todos os vetores ao centróide mais próximo (multithread).
fn assign_all(vectors: &[[f32; DIM]], centroids: &[f32], k: usize) -> Vec<u32> {
    let n = vectors.len();
    let mut assign = vec![0u32; n];
    let threads = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(4);
    let chunk = n.div_ceil(threads);

    std::thread::scope(|s| {
        for (t, out) in assign.chunks_mut(chunk).enumerate() {
            let start = t * chunk;
            let vectors = &vectors;
            let centroids = &centroids;
            s.spawn(move || {
                for (j, slot) in out.iter_mut().enumerate() {
                    *slot = nearest(&vectors[start + j], centroids, k).0 as u32;
                }
            });
        }
    });
    assign
}

// ---------- escrita do blob ----------

fn write_blob(
    path: &str,
    n: usize,
    k: usize,
    centroids: &[f32],
    offsets: &[u32],
    vectors: &[i16],
    labels: &[u8],
) {
    let f = std::fs::File::create(path).expect("criar blob");
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    w.write_all(&MAGIC.to_le_bytes()).unwrap();
    w.write_all(&(n as u32).to_le_bytes()).unwrap();
    w.write_all(&(k as u32).to_le_bytes()).unwrap();
    w.write_all(&0u32.to_le_bytes()).unwrap(); // reservado
    write_slice(&mut w, centroids);
    write_slice(&mut w, offsets);
    write_slice(&mut w, vectors);
    w.write_all(labels).unwrap();
    w.flush().unwrap();
}

fn write_slice<T: Copy, W: Write>(w: &mut W, data: &[T]) {
    let bytes = unsafe {
        std::slice::from_raw_parts(data.as_ptr() as *const u8, std::mem::size_of_val(data))
    };
    w.write_all(bytes).unwrap();
}
