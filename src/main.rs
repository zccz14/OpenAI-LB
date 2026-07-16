use anyhow::Result;
use openai_lb::{
    AppState,
    config::{BootstrapConfig, Config},
    db, router,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("openai_lb=info,tower_http=info")),
        )
        .init();
    let bootstrap = BootstrapConfig::load()?;
    let listen = bootstrap.listen;
    let pool = db::connect(&bootstrap.database_path, &bootstrap.encryption_key).await?;
    let config = Config::load(bootstrap, &pool).await?;
    let state = AppState::new(config, pool).await?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "OpenAI-LB listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
