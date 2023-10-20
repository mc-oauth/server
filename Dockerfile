FROM rust:slim-bullseye as builder
WORKDIR /usr/src/authentify
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/authentify /usr/local/bin/authentify
EXPOSE 8080 25565
CMD ["authentify"]
