# rinha-de-backend-2026 — karlos-rust

Detecção de fraude por busca vetorial (k-NN, k=5, distância euclidiana) para a
[Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026).

## Abordagem

- **Linguagem:** Rust (sem GC → cauda de latência previsível).
- **Busca:** índice **IVF** (inverted file). k-means agrupa os 3.000.000 de
  vetores em ~2048 clusters; cada consulta sonda apenas os `nprobe` clusters
  mais próximos e faz busca exata dentro deles. Toca ~dezenas de milhares de
  vetores em vez de 3M → p99 sub-ms sustentando ~900 req/s.
- **Memória:** vetores quantizados em `i16` (escala 10000 = sem perda, pad 16
  dims = 32 B), reordenados por cluster, num blob `mmap`-ável. ~96 MB/instância.
- **Distância:** euclidiana ao quadrado em `i16` com acumulador `i32` (habilita
  AVX2 `vpmaddwd`).
- **Pré-processamento:** o índice é construído fora do runtime (`build_index`)
  e embutido na imagem. O startup só faz `mmap` → `/ready` imediato.
- **HTTP:** servidor próprio mínimo (HTTP/1.1, uma thread por conexão keep-alive),
  escutando em **unix socket**.
- **Load balancer:** binário Rust próprio (`lb`) — proxy TCP→unix round-robin,
  sem nginx (evita o overhead de TCP loopback). APIs e LB compartilham um
  `tmpfs` e são pinados a cores via `cpuset`.

## Estrutura

- `src/lib.rs` — vetorização (14 dims), parsing de timestamp, formato do índice e busca IVF.
- `src/bin/build_index.rs` — pré-processa `references.json.gz` no blob `index.bin`.
- `src/main.rs` — servidor HTTP (`GET /ready`, `POST /fraud-score`), unix socket.
- `src/bin/lb.rs` — load balancer próprio (proxy TCP→unix, round-robin).
- `src/bin/validate.rs` — mede recall/score contra o gabarito (offline).

## Build do índice

```sh
cargo run --release --bin build_index -- references.json.gz index.bin 2048
```

## Rodar localmente

```sh
INDEX_PATH=index.bin NPROBE=24 cargo run --release --bin server
```

A branch `submission` contém apenas `docker-compose.yml`, `nginx.conf` e `info.json`.
