# ---- Builder Stage ----
# Use the official Rust image as a build environment.
FROM rust:1.82 as builder

# Set the working directory.
WORKDIR /usr/src/sentinel_rust_core

# Copy the Cargo manifest and lock file.
COPY sentinel_backend/sentinel_rust_core/Cargo.toml ./

# Create a dummy src directory with a main.rs file to cache dependencies.
# This layer will only be rebuilt if Cargo.toml or Cargo.lock changes.
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/sentinel_rust_core*

# Copy the actual source code.
COPY sentinel_backend/sentinel_rust_core/src ./src

# Build the application.
RUN cargo build --release

# ---- Final Stage ----
# Use a minimal image for the final container.
FROM debian:bookworm-slim

# Set the working directory.
WORKDIR /usr/local/bin

# Copy the compiled binary from the builder stage.
COPY --from=builder /usr/src/sentinel_rust_core/target/release/sentinel-rust-core .

# Expose the port the service will run on.
EXPOSE 8088

# Set the command to run the service.
CMD ["./sentinel-rust-core"]