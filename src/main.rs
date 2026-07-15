use anyhow::Result;
use openai_lb::{AppState, config::Config, db, router};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("openai_lb=info,tower_http=info")),
        )
        .init();
    let config = Config::from_env()?;
    let listen = config.listen;
    let pool = db::connect(&config.database_url).await?;
    let state = AppState::new(config, pool)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "OpenAI-LB listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
