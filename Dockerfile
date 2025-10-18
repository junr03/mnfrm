    # Stage 1: Build the Rust binary
    FROM rust:latest as builder

    # Set the working directory inside the container
    WORKDIR /app

    # Copy the Cargo.toml and Cargo.lock files
    COPY Cargo.toml Cargo.lock ./

    # Cache dependencies by building a dummy project
    RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release
    RUN rm -rf target/release/deps/mnfrm* src

    # Copy the source code
    COPY src ./src

    # Build the release binary
    RUN cargo build --release

    # Stage 2: Create a minimal runtime image
    FROM debian:stable-slim

    # Set the working directory
    WORKDIR /app

    # Copy the compiled binary from the builder stage
    COPY --from=builder /app/target/release/mnfrm .

    # Define the command to run the application
    CMD ["./mnfrm"]
