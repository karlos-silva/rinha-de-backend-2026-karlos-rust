//! Diagnóstico offline: roda k-NN EXATO (brute force sobre os 3M) para todas as
//! queries de teste e reporta FP/FN. Compara o resultado exato i16 com o esperado
//! para descobrir se os erros do IVF são de recall (busca aproximada) ou de
//! cálculo (inteiro vs f32 / desempate). Não vai para produção.
//!
//! Uso: diag <index.bin> <test-data.json>

use memmap2::Mmap;
use rinha_fraud::consts::PAD;
use rinha_fraud::index::{dist_i16, Index};
use rinha_fraud::vectorize::{quantize, vectorize, Request};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::time::Instant;

#[derive(Deserialize)]
struct Entry<'a> {
    #[serde(borrow)]
    request: &'a RawValue,
    expected_approved: bool,
}
#[derive(Deserialize)]
struct TestFile<'a> {
    #[serde(borrow)]
    entries: Vec<Entry<'a>>,
}

#[inline]
fn is_fraud(labels: &[u8], i: usize) -> bool {
    (labels[i >> 3] >> (i & 7)) & 1 == 1
}

/// k-NN exato i16; retorna (approved, fraude_count).
fn exact(q: &[i16; PAD], vectors: &[i16], labels: &[u8], n: usize) -> (bool, u32) {
    let mut td = [i32::MAX; 5];
    let mut tf = [false; 5];
    for i in 0..n {
        let d = dist_i16(q, &vectors[i * PAD..i * PAD + PAD]);
        if d < td[4] {
            let mut p = 4;
            while p > 0 && td[p - 1] > d {
                td[p] = td[p - 1];
                tf[p] = tf[p - 1];
                p -= 1;
            }
            td[p] = d;
            tf[p] = is_fraud(labels, i);
        }
    }
    let frauds = tf.iter().filter(|&&f| f).count() as u32;
    (frauds < 3, frauds) // approved se fraud_score < 0.6 (i.e. <=2 fraudes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let index_path = args.get(1).map(String::as_str).unwrap_or("index.bin");
    let test_path = args.get(2).map(String::as_str).unwrap_or("test-data.json");

    let file = std::fs::File::open(index_path).expect("abrir índice");
    let mmap = unsafe { Mmap::map(&file).expect("mmap") };
    let index = Index::from_bytes(&mmap);
    let n = index.num_vectors;
    let vectors = index.vectors;
    let labels = index.labels;

    let test_raw = std::fs::read_to_string(test_path).expect("ler test-data");
    let test: TestFile = serde_json::from_str(&test_raw).expect("parse");
    let queries: Vec<([i16; PAD], bool)> = test
        .entries
        .iter()
        .map(|e| {
            let req: Request = serde_json::from_str(e.request.get()).unwrap();
            (quantize(&vectorize(&req)), e.expected_approved)
        })
        .collect();
    eprintln!("[diag] {} queries, brute force exato sobre {n} vetores...", queries.len());

    let t0 = Instant::now();
    let threads = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(4);
    let chunk = queries.len().div_ceil(threads);
    let results: Vec<(u32, u32, Vec<(usize, u32, bool)>)> = std::thread::scope(|s| {
        let mut hs = Vec::new();
        for (t, qs) in queries.chunks(chunk).enumerate() {
            let base = t * chunk;
            hs.push(s.spawn(move || {
                let mut fp = 0u32;
                let mut fn_ = 0u32;
                let mut miss = Vec::new();
                for (j, (q, exp)) in qs.iter().enumerate() {
                    let (approved, frauds) = exact(q, vectors, labels, n);
                    match (approved, *exp) {
                        (true, false) => {
                            fn_ += 1;
                            miss.push((base + j, frauds, *exp));
                        }
                        (false, true) => {
                            fp += 1;
                            miss.push((base + j, frauds, *exp));
                        }
                        _ => {}
                    }
                }
                (fp, fn_, miss)
            }));
        }
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut fp = 0;
    let mut fn_ = 0;
    let mut all_miss = Vec::new();
    for (a, b, m) in results {
        fp += a;
        fn_ += b;
        all_miss.extend(m);
    }
    eprintln!("[diag] brute force exato i16: FP={fp} FN={fn_} em {:?}", t0.elapsed());
    eprintln!("[diag] casos divergentes (idx, fraudes_encontradas/5, expected_approved):");
    for (idx, frauds, exp) in all_miss.iter().take(40) {
        eprintln!("  query #{idx}: {frauds}/5 fraudes, esperado approved={exp}");
    }
}
