//! Núcleo compartilhado entre o builder do índice, o validador e o servidor.
//!
//! Pipeline: payload JSON -> vetor f32 de 14 dimensões (normalizado) -> i16
//! quantizado (escala 1000, pad 16) -> busca IVF -> fraud_score.

pub mod consts {
    /// Dimensões reais do vetor de detecção.
    pub const DIM: usize = 14;
    /// Dimensões com padding (múltiplo de 8/16 para autovetorização).
    pub const PAD: usize = 16;
    /// Fator de quantização f32 -> i16. 10000 = sem perda (os dados têm 4 casas);
    /// valores em [-1,1] viram [-10000,10000] (cabe em i16). A soma de quadrados
    /// é acumulada em i64 (ver dist_i16) para evitar overflow.
    pub const SCALE: f32 = 10000.0;

    // normalization.json (constantes fixas do desafio).
    pub const MAX_AMOUNT: f32 = 10000.0;
    pub const MAX_INSTALLMENTS: f32 = 12.0;
    pub const AMOUNT_VS_AVG_RATIO: f32 = 10.0;
    pub const MAX_MINUTES: f32 = 1440.0;
    pub const MAX_KM: f32 = 1000.0;
    pub const MAX_TX_COUNT_24H: f32 = 20.0;
    pub const MAX_MERCHANT_AVG_AMOUNT: f32 = 10000.0;

    /// mcc_risk.json. Valor padrão 0.5 quando o MCC não está na tabela.
    #[inline]
    pub fn mcc_risk(mcc: &str) -> f32 {
        match mcc {
            "5411" => 0.15,
            "5812" => 0.30,
            "5912" => 0.20,
            "5944" => 0.45,
            "7801" => 0.80,
            "7802" => 0.75,
            "7995" => 0.85,
            "4511" => 0.35,
            "5311" => 0.25,
            "5999" => 0.50,
            _ => 0.5,
        }
    }
}

pub mod timeutil {
    /// Converte um timestamp ISO-8601 UTC ("YYYY-MM-DDThh:mm:ssZ") em
    /// (segundos desde epoch, hora 0-23, dia da semana com seg=0..dom=6).
    /// Faz parsing por posição fixa — o contrato garante esse formato.
    #[inline]
    pub fn parse_iso(s: &str) -> Option<(i64, u32, u32)> {
        let b = s.as_bytes();
        if b.len() < 19 {
            return None;
        }
        let d = |i: usize| (b[i] - b'0') as i64;
        let year = d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3);
        let month = d(5) * 10 + d(6);
        let day = d(8) * 10 + d(9);
        let hour = d(11) * 10 + d(12);
        let min = d(14) * 10 + d(15);
        let sec = d(17) * 10 + d(18);

        let days = days_from_civil(year, month, day);
        let epoch = days * 86400 + hour * 3600 + min * 60 + sec;
        // 1970-01-01 é quinta (Sun=0..Sat=6 => 4). Converte para seg=0..dom=6.
        let wd_sun0 = ((days % 7) + 4) % 7; // days >= 0 nas datas do desafio
        let dow_mon0 = ((wd_sun0 + 6) % 7) as u32;
        Some((epoch, hour as u32, dow_mon0))
    }

    /// Algoritmo days-from-civil (Howard Hinnant): dias desde 1970-01-01.
    #[inline]
    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = y - (m <= 2) as i64;
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    }
}

pub mod vectorize {
    use crate::consts::*;
    use crate::timeutil::parse_iso;
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct Transaction {
        pub amount: f32,
        pub installments: f32,
        pub requested_at: String,
    }

    #[derive(Deserialize)]
    pub struct Customer<'a> {
        pub avg_amount: f32,
        pub tx_count_24h: f32,
        #[serde(borrow, default)]
        pub known_merchants: Vec<&'a str>,
    }

    #[derive(Deserialize)]
    pub struct Merchant<'a> {
        pub id: &'a str,
        pub mcc: &'a str,
        pub avg_amount: f32,
    }

    #[derive(Deserialize)]
    pub struct Terminal {
        pub is_online: bool,
        pub card_present: bool,
        pub km_from_home: f32,
    }

    #[derive(Deserialize)]
    pub struct LastTx {
        pub timestamp: String,
        pub km_from_current: f32,
    }

    #[derive(Deserialize)]
    pub struct Request<'a> {
        pub transaction: Transaction,
        #[serde(borrow)]
        pub customer: Customer<'a>,
        #[serde(borrow)]
        pub merchant: Merchant<'a>,
        pub terminal: Terminal,
        #[serde(default)]
        pub last_transaction: Option<LastTx>,
    }

    #[inline]
    fn clamp01(x: f32) -> f32 {
        x.clamp(0.0, 1.0)
    }

    /// Transforma o payload nas 14 dimensões normalizadas (REGRAS_DE_DETECCAO.md).
    pub fn vectorize(req: &Request) -> [f32; DIM] {
        let t = &req.transaction;
        let c = &req.customer;
        let m = &req.merchant;
        let term = &req.terminal;

        let (req_epoch, hour, dow) = parse_iso(&t.requested_at).unwrap_or((0, 0, 0));

        let (minutes_since, km_last) = match &req.last_transaction {
            Some(lt) => {
                let last_epoch = parse_iso(&lt.timestamp).map(|x| x.0).unwrap_or(req_epoch);
                let minutes = (req_epoch - last_epoch) as f32 / 60.0;
                (
                    clamp01(minutes / MAX_MINUTES),
                    clamp01(lt.km_from_current / MAX_KM),
                )
            }
            // Sentinela -1 para "sem transação anterior".
            None => (-1.0, -1.0),
        };

        let amount_vs_avg = if c.avg_amount > 0.0 {
            clamp01((t.amount / c.avg_amount) / AMOUNT_VS_AVG_RATIO)
        } else {
            1.0
        };

        let unknown_merchant = if c.known_merchants.iter().any(|&k| k == m.id) {
            0.0
        } else {
            1.0
        };

        [
            clamp01(t.amount / MAX_AMOUNT),                 // 0 amount
            clamp01(t.installments / MAX_INSTALLMENTS),     // 1 installments
            amount_vs_avg,                                  // 2 amount_vs_avg
            hour as f32 / 23.0,                             // 3 hour_of_day
            dow as f32 / 6.0,                               // 4 day_of_week
            minutes_since,                                  // 5 minutes_since_last_tx
            km_last,                                        // 6 km_from_last_tx
            clamp01(term.km_from_home / MAX_KM),            // 7 km_from_home
            clamp01(c.tx_count_24h / MAX_TX_COUNT_24H),     // 8 tx_count_24h
            if term.is_online { 1.0 } else { 0.0 },         // 9 is_online
            if term.card_present { 1.0 } else { 0.0 },      // 10 card_present
            unknown_merchant,                               // 11 unknown_merchant
            mcc_risk(m.mcc),                                // 12 mcc_risk
            clamp01(m.avg_amount / MAX_MERCHANT_AVG_AMOUNT),// 13 merchant_avg_amount
        ]
    }

    /// Quantiza o vetor f32 para i16 (escala 1000) com padding até PAD.
    #[inline]
    pub fn quantize(v: &[f32; DIM]) -> [i16; PAD] {
        let mut out = [0i16; PAD];
        for i in 0..DIM {
            out[i] = (v[i] * SCALE).round() as i16;
        }
        out
    }
}

pub mod index {
    use crate::consts::*;

    /// Layout do blob (little-endian, mmap-ável):
    ///   [0]   magic           u32 = 0x52494E48 ("RINH")
    ///   [4]   num_vectors     u32
    ///   [8]   num_clusters    u32
    ///   [12]  _reserved       u32
    ///   centroids:  num_clusters * DIM  f32
    ///   offsets:    (num_clusters + 1)  u32   (prefix sum nos vetores)
    ///   vectors:    num_vectors * PAD   i16   (reordenados por cluster)
    ///   labels:     ceil(num_vectors/8) u8    (bitset: 1 = fraude)
    pub const MAGIC: u32 = 0x5249_4E48;

    pub struct Index<'a> {
        pub num_vectors: usize,
        pub num_clusters: usize,
        pub centroids: &'a [f32], // num_clusters * DIM
        pub offsets: &'a [u32],   // num_clusters + 1
        pub vectors: &'a [i16],   // num_vectors * PAD
        pub labels: &'a [u8],     // bitset
    }

    #[inline]
    fn rd_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    impl<'a> Index<'a> {
        pub fn from_bytes(b: &'a [u8]) -> Index<'a> {
            assert!(rd_u32(b, 0) == MAGIC, "magic inválido no blob do índice");
            let num_vectors = rd_u32(b, 4) as usize;
            let num_clusters = rd_u32(b, 8) as usize;

            let mut off = 16;
            let cen_len = num_clusters * DIM;
            let centroids = unsafe {
                std::slice::from_raw_parts(b.as_ptr().add(off) as *const f32, cen_len)
            };
            off += cen_len * 4;

            let off_len = num_clusters + 1;
            let offsets = unsafe {
                std::slice::from_raw_parts(b.as_ptr().add(off) as *const u32, off_len)
            };
            off += off_len * 4;

            let vec_len = num_vectors * PAD;
            let vectors = unsafe {
                std::slice::from_raw_parts(b.as_ptr().add(off) as *const i16, vec_len)
            };
            off += vec_len * 2;

            let lab_len = num_vectors.div_ceil(8);
            let labels = &b[off..off + lab_len];

            Index { num_vectors, num_clusters, centroids, offsets, vectors, labels }
        }

        #[inline]
        fn is_fraud(&self, i: usize) -> bool {
            (self.labels[i >> 3] >> (i & 7)) & 1 == 1
        }

        /// Busca IVF: encontra os `nprobe` clusters mais próximos (em f32) e
        /// faz busca exata i16 dentro deles, mantendo os 5 vizinhos mais próximos.
        /// Retorna o fraud_score (frações de fraudes entre os 5).
        pub fn fraud_score(
            &self,
            q_f32: &[f32; DIM],
            q_i16: &[i16; PAD],
            nprobe: usize,
        ) -> f32 {
            // 1) clusters mais próximos do query (distância f32 aos centróides).
            // Heap-máx simples de tamanho nprobe sobre (dist, cluster).
            let np = nprobe.min(self.num_clusters);
            let mut best: Vec<(f32, u32)> = Vec::with_capacity(np + 1);
            let mut worst = f32::INFINITY;
            for c in 0..self.num_clusters {
                let cen = &self.centroids[c * DIM..c * DIM + DIM];
                let mut dist = 0.0f32;
                for k in 0..DIM {
                    let d = q_f32[k] - cen[k];
                    dist += d * d;
                }
                if best.len() < np {
                    best.push((dist, c as u32));
                    if best.len() == np {
                        worst = best.iter().fold(0.0, |a, &(d, _)| a.max(d));
                    }
                } else if dist < worst {
                    // substitui o pior
                    let mut wi = 0;
                    let mut wd = best[0].0;
                    for (i, &(d, _)) in best.iter().enumerate() {
                        if d > wd {
                            wd = d;
                            wi = i;
                        }
                    }
                    best[wi] = (dist, c as u32);
                    worst = best.iter().fold(0.0, |a, &(d, _)| a.max(d));
                }
            }

            // 2) busca exata i16 dentro dos clusters escolhidos -> top 5.
            let mut top_d = [i32::MAX; 5];
            let mut top_f = [false; 5];
            for &(_, c) in &best {
                let c = c as usize;
                let start = self.offsets[c] as usize;
                let end = self.offsets[c + 1] as usize;
                let base = &self.vectors[start * PAD..end * PAD];
                for (j, chunk) in base.chunks_exact(PAD).enumerate() {
                    let dist = dist_i16(q_i16, chunk);
                    if dist < top_d[4] {
                        // insere mantendo top_d ordenado crescente
                        let mut p = 4;
                        while p > 0 && top_d[p - 1] > dist {
                            top_d[p] = top_d[p - 1];
                            top_f[p] = top_f[p - 1];
                            p -= 1;
                        }
                        top_d[p] = dist;
                        top_f[p] = self.is_fraud(start + j);
                    }
                }
            }

            let frauds = top_f.iter().filter(|&&f| f).count();
            frauds as f32 / 5.0
        }
    }

    /// Distância euclidiana ao quadrado em i16 (escala 10000). Loop de tamanho
    /// fixo PAD para o LLVM emitir AVX2 (vpmaddwd: multiplica pares de i16 e
    /// acumula em i32). A soma máxima é 2.0e9 (12 dims [0,1] + 2 dims sentinela
    /// [-1,1], escala 10000) < i32::MAX (2.147e9), então o i32 nunca estoura.
    #[inline]
    pub fn dist_i16(a: &[i16; PAD], b: &[i16]) -> i32 {
        let mut acc = 0i32;
        for i in 0..PAD {
            let d = a[i] as i32 - b[i] as i32;
            acc += d * d;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::timeutil::parse_iso;

    #[test]
    fn iso_legit_example() {
        // 2026-03-11T18:45:53Z -> hora 18, dow 2 (qua), conforme REGRAS_DE_DETECCAO.md
        let (_, h, dow) = parse_iso("2026-03-11T18:45:53Z").unwrap();
        assert_eq!(h, 18);
        assert_eq!(dow, 2);
    }

    #[test]
    fn iso_fraud_example() {
        // 2026-03-14T05:15:12Z -> hora 5, dow 5 (sab) -> 5/6 = 0.8333
        let (_, h, dow) = parse_iso("2026-03-14T05:15:12Z").unwrap();
        assert_eq!(h, 5);
        assert_eq!(dow, 5);
    }
}
