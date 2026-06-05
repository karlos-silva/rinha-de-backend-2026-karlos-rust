//! Valida recall e score de detecção contra o gabarito de test-data.json.
//! NÃO é usado em produção — só mede a qualidade do IVF offline.
//!
//! Uso: validate <index.bin> <test-data.json> [nprobe1,nprobe2,...]

use memmap2::Mmap;
use rinha_fraud::index::Index;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let index_path = args.get(1).map(String::as_str).unwrap_or("index.bin");
    let test_path = args.get(2).map(String::as_str).unwrap_or("test-data.json");
    let nprobes: Vec<usize> = args
        .get(3)
        .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_else(|| vec![8, 16, 24, 32, 48, 64]);

    let file = std::fs::File::open(index_path).expect("abrir índice");
    let mmap = unsafe { Mmap::map(&file).expect("mmap") };
    let index = Index::from_bytes(&mmap);
    eprintln!("[validate] {} vetores, {} clusters", index.num_vectors, index.num_clusters);

    let test_raw = std::fs::read_to_string(test_path).expect("ler test-data");
    let test: TestFile = serde_json::from_str(&test_raw).expect("parse test-data");
    let n = test.entries.len();
    eprintln!("[validate] {n} entradas de teste\n");

    // Pré-vetoriza todas as entradas uma vez.
    let mut queries: Vec<([f32; 14], [i16; 16], bool)> = Vec::with_capacity(n);
    for e in &test.entries {
        let req: Request = serde_json::from_str(e.request.get()).expect("parse request");
        let v = vectorize(&req);
        let q = quantize(&v);
        queries.push((v, q, e.expected_approved));
    }

    println!("{:>6} | {:>6} {:>6} {:>6} {:>6} | {:>8} | {:>9} | {:>10}",
        "nprobe", "TP", "TN", "FP", "FN", "falha%", "det_score", "us/query");

    for &np in &nprobes {
        let mut tp = 0u32;
        let mut tn = 0u32;
        let mut fp = 0u32;
        let mut fn_ = 0u32;

        let t0 = Instant::now();
        for (v, q, expected_approved) in &queries {
            let fs = index.fraud_score(v, q, np);
            let approved = fs < 0.6;
            match (approved, *expected_approved) {
                (true, true) => tn += 1,   // legítima aprovada corretamente
                (false, false) => tp += 1, // fraude negada corretamente
                (true, false) => fn_ += 1, // fraude aprovada (escapou)
                (false, true) => fp += 1,  // legítima negada (bloqueio errado)
            }
        }
        let us = t0.elapsed().as_secs_f64() * 1e6 / n as f64;

        let total = (tp + tn + fp + fn_) as f64;
        let e_weighted = (fp as f64) + 3.0 * (fn_ as f64);
        let failures = (fp + fn_) as f64;
        let failure_rate = failures / total;
        let det_score = if failure_rate > 0.15 {
            -3000.0
        } else {
            let epsilon = (e_weighted / total).max(0.001);
            1000.0 * (1.0 / epsilon).log10() - 300.0 * (1.0 + e_weighted).log10()
        };

        println!("{:>6} | {:>6} {:>6} {:>6} {:>6} | {:>7.2}% | {:>9.1} | {:>10.2}",
            np, tp, tn, fp, fn_, failure_rate * 100.0, det_score, us);
    }
}
