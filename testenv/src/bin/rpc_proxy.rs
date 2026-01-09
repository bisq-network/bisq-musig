use axum::Router;
use axum_reverse_proxy::ReverseProxy;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: rpc_proxy <target_port> <listen_port>");
        std::process::exit(1);
    }
    let target_port: u16 = args[1].parse()?;
    let listen_port: u16 = args[2].parse()?;

    let target_url = format!("http://localhost:{}", target_port);

    eprintln!("Starting RPC proxy...");
    eprintln!("Forwarding all requests to {}", target_url);

    let proxy = ReverseProxy::new("/", &target_url);

    let app: Router = proxy.into();

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = TcpListener::bind(addr).await?;

    eprintln!("RPC proxy listening at: http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
