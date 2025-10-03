use std::error::Error;
use std::sync::Arc;
use std::collections::HashMap;

use opendr::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
use opendr::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("config/log4rs.yml", Default::default()).unwrap();

    // Create mock backend with credentials from config/server.toml
    // cn=manager,dc=example,dc=com with password Admin@123
    let mut backend = MockBackend::from_credentials([(
        "cn=manager,dc=example,dc=com",
        b"Admin@123".to_vec(),
    )]);

    // Add base structure entries
    let base_dn_entry = DirectoryEntry::new(
        "dc=example,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organization".to_string()]),
            ("o".to_string(), vec!["password".to_string()]),
            ("description".to_string(), vec!["password".to_string()]),
        ])
    );
    backend.add_entry(base_dn_entry, vec![]).await?;

    let people_ou_entry = DirectoryEntry::new(
        "ou=People,dc=example,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["People".to_string()]),
            ("description".to_string(), vec!["People container".to_string()]),
        ])
    );
    backend.add_entry(people_ou_entry, vec![]).await?;

    let groups_ou_entry = DirectoryEntry::new(
        "ou=Groups,dc=example,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["Groups".to_string()]),
            ("description".to_string(), vec!["Groups container".to_string()]),
        ])
    );
    backend.add_entry(groups_ou_entry, vec![]).await?;

    let apps_ou_entry = DirectoryEntry::new(
        "ou=Applications,dc=example,dc=com",
        HashMap::from([
            ("objectClass".to_string(), vec!["top".to_string(), "organizationalUnit".to_string()]),
            ("ou".to_string(), vec!["Applications".to_string()]),
            ("description".to_string(), vec!["Applications container".to_string()]),
        ])
    );
    backend.add_entry(apps_ou_entry, vec![]).await?;

    let backend: Arc<dyn DirectoryBackend> = Arc::new(backend);

    server::run("127.0.0.1:1389", backend)
        .await
        .map_err(|err| Box::new(err) as Box<dyn Error>)
}
