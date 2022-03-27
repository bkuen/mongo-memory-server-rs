# Mongo In-Memory Server for Rust unit tests

[![example workflow](https://github.com/bkuen/mongo-memory-server-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/bkuen/mongo-memory-server-rs/actions/workflows/rust.yml)
[![made-with-rust](https://img.shields.io/badge/Made%20with-Rust-1f425f.svg)](https://www.rust-lang.org/)
[![Maintainer](https://img.shields.io/badge/maintainer-bkuen-blue)](https://github.com/bkuen)
[![GitHub license](https://badgen.net/github/license/bkuen/mongo-memory-server-rs)](https://github.com/bkuen/mongo-memory-server-rs/blob/main/LICENSE)
[![GitHub branches](https://badgen.net/github/branches/bkuen/mongo-memory-server-rs)](https://github.com/bkuen/mongo-memory-server-rs)
[![GitHub releases](https://badgen.net/github/releases/bkuen/mongo-memory-server-rs)](https://github.com/bkuen/mongo-memory-server-rs/releases/)
[![GitHub latest commit](https://badgen.net/github/last-commit/bkuen/mongo-memory-server-rs/main)](https://github.com/bkuen/mongo-memory-server-rs/commit/)
[![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/bkuen/mongo-memory-server-rs)

This package spins up a `MongoDB` instance programmatically from within `Rust`.
It is the counterpart to the NodeJS implementation of [nodkz](https://github.com/nodkz) 's npm package [mongodb-memory-server](https://github.com/nodkz/mongodb-memory-server).

The crate is currently in active development and is not yet fully ready. At the moment, only `MongoDB` version `5.2.0` is tested.
If you encounter any errors with different versions, feel free to contact us.

The crate will automatically download the binary to the corresponding version if it doesn't yet exist.
Make sure to have a stable internet connection because a failed download might end up in undefined behaviour at this point in the development cycle.

## Requirements

To use this crate, make sure the following requirements are fulfilled:
* Supported operating systems: `Windows`, `Debian`, `Ubuntu`, `Mint (not tested)`
* Supported architectures: `ia32`, `x86_64`, `arm64`, `aarch64`
* If you work on `unix`-like operating systems. Make sure, `libssl` is installed. Otherwise,
the `MongoDB` binaries could not extracted.
	```bash
	$ apt install -y libssl-dev
	```

## Example

The library works great with the [test_context](https://docs.rs/test-context/latest/test_context/) crate.
Therefore, add the following to your `Cargo.toml` to use this library.

```toml
[dev-dependencies]
async-trait = "0.1.52"
mongo-memory-server = "0.1.0"
test-context = "0.1.3"
tokio = { version = "1.17.0", features = ["test-util"] }
```
Afterwards, some setup tasks are required

```rust
use mongo_memory_server::server::{MongoServer, MongoOptions};
use test_context::{test_context, AsyncTestContext};
use test_context::futures;

struct MyTestContext;

#[async_trait::async_trait]
impl AsyncTestContext for MyTestContext {
    async fn setup() -> MyTestContext {
        let mongo_options = MongoOptions::builder()
            .host("127.0.0.1")
            .port(28000)
            .build();

        let mut server = MongoServer::new(mongo_options).unwrap();
        let _ = server.start().await.unwrap();

        MyTestContext{}
    }
}
```

Of course, you could use the library with different testing setups as well.

## Sponsors

This project is sponsored by