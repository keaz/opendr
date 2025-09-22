use std::error::Error;
use std::sync::Arc;

use opendr::backend::{DirectoryBackend, MockBackend};
use opendr::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("config/log4rs.yml", Default::default()).unwrap();

    let backend: Arc<dyn DirectoryBackend> = Arc::new(MockBackend::default());

    server::run("127.0.0.1:1389", backend)
        .await
        .map_err(|err| Box::new(err) as Box<dyn Error>)
}
