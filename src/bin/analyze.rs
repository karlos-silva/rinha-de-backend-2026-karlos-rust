//! Análise offline do dataset: quantos vetores ÚNICOS existem entre os 3M e se
//! duplicatas do mesmo vetor têm rótulos consistentes. Define se dá pra dedup +
//! brute force exato rápido. Uso: analyze <references.json.gz>

use flate2::read::MultiGzDecoder;
use rinha_fraud::consts::{DIM, SCALE};
use std::collections::HashMap;
use std::io::Read;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "references.json.gz".into());
    let f = std::fs::File::open(&path).expect("abrir");
    let mut raw = Vec::new();
    MultiGzDecoder::new(f).read_to_end(&mut raw).expect("gz");

    // key = [i16;14] (quantizado escala 10000, idêntico ao runtime). value = (fraude, legit)
    let mut map: HashMap<[i16; DIM], (u32, u32)> = HashMap::with_capacity(1 << 20);
    let mut total = 0u64;

    let n = raw.len();
    let data = &raw[..];
    let mut i = 0;
    while i < n && data[i] != b'[' { i += 1; }
    i += 1;
    loop {
        while i < n && matches!(data[i], b' '|b'\n'|b'\r'|b'\t'|b','|b'{'|b'}') { i += 1; }
        if i >= n || data[i] == b']' { break; }
        while i < n && data[i] != b'[' { i += 1; }
        i += 1;
        let mut key = [0i16; DIM];
        for slot in key.iter_mut() {
            while i < n && matches!(data[i], b' '|b'\n'|b'\r'|b'\t'|b',') { i += 1; }
            let start = i;
            while i < n && !matches!(data[i], b','|b']'|b' '|b'\n'|b'\r'|b'\t') { i += 1; }
            let v: f32 = unsafe { std::str::from_utf8_unchecked(&data[start..i]) }.parse().unwrap();
            *slot = (v * SCALE).round() as i16;
        }
        while i < n && data[i] != b']' { i += 1; }
        i += 1;
        while i < n && data[i] != b':' { i += 1; }
        i += 1;
        while i < n && data[i] != b'"' { i += 1; }
        i += 1;
        let ls = i;
        while i < n && data[i] != b'"' { i += 1; }
        let fraud = &data[ls..i] == b"fraud";
        i += 1;

        let e = map.entry(key).or_insert((0, 0));
        if fraud { e.0 += 1; } else { e.1 += 1; }
        total += 1;
    }

    let unique = map.len();
    let mut mixed = 0u64; // pontos com fraude E legit
    let mut max_dups = 0u32;
    for (_, &(fr, le)) in &map {
        if fr > 0 && le > 0 { mixed += 1; }
        max_dups = max_dups.max(fr + le);
    }
    println!("total vetores : {total}");
    println!("vetores únicos: {unique}  ({:.2}% do total)", unique as f64 / total as f64 * 100.0);
    println!("pontos mistos (fraude+legit): {mixed}  ({:.4}% dos únicos)", mixed as f64 / unique as f64 * 100.0);
    println!("máx duplicatas de um ponto   : {max_dups}");
}
