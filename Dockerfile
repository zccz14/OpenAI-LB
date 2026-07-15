FROM node:24-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run check

FROM rust:1.93-bookworm AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY --from=web /src/web /src/web
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=rust /src/target/release/openai-lb /usr/local/bin/openai-lb
VOLUME ["/data"]
ENV LISTEN_ADDR=0.0.0.0:8080 DATABASE_URL=sqlite:///data/openai-lb.sqlite?mode=rwc
EXPOSE 8080
ENTRYPOINT ["openai-lb"]
