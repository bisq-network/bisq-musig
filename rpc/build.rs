use std::prelude::rust_2021::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &["src/main/proto/rpc.proto", "src/main/proto/wallet.proto"],
        &["src/main/proto"],
    )?;
    Ok(())
}
