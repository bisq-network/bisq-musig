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
        eprintln!("Usage: esplora_proxy <api_url> <port>");
        std::process::exit(1);
    }
    let api_url = &format!("http://{}", &args[1]);
    let port: u16 = args[2].parse()?;

    eprintln!("Starting Esplora UI proxy...");
    eprintln!("Forwarding /api to {}", api_url);
    eprintln!("Forwarding / to http://localhost:8888");

    let api = ReverseProxy::new("/api", api_url);
    let frontend = ReverseProxy::new("/", "http://localhost:8888");

    let app: Router = api.into();
    let app = app.fallback_service(frontend);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    eprintln!("Esplora UI served at: http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
