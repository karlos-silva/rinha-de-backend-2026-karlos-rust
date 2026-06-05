# Imagem da API. Compila só o binário `server` e embute o índice pré-gerado
# (index.bin), gerado fora do runtime com `build_index`. Startup = só mmap.
#
# Construir para linux/amd64 (Mac Mini Late 2014 = Haswell, AVX2):
#   docker buildx build --platform linux/amd64 -t ghcr.io/karlos-silva/rinha-fraud:latest --push .

FROM --platform=linux/amd64 rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# x86-64-v3 == nível Haswell (AVX2 + FMA), habilita autovetorização.
ENV RUSTFLAGS="-C target-cpu=x86-64-v3"
RUN cargo build --release --bin server --bin lb

FROM --platform=linux/amd64 debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/server /app/server
COPY --from=builder /app/target/release/lb /app/lb
COPY index.bin /app/index.bin
ENV INDEX_PATH=/app/index.bin
# A mesma imagem serve a API (CMD padrão) e o LB (command: /app/lb no compose).
CMD ["/app/server"]
