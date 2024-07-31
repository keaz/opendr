use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize)]
pub struct LdapEntry {
    dn: String,
    attributes: Vec<Attribute>,
}

#[derive(Serialize, Deserialize)]
pub struct Attribute {
    key: String,
    value: Vec<String>,
}

impl LdapEntry {
    fn new(dn: String, attributes: Vec<Attribute>) -> Self {
        LdapEntry { dn, attributes }
    }

    pub async fn to_file(&self, file_path: &Path) -> std::io::Result<()> {
        let serialized = bincode::serialize(self).unwrap();
        let mut file = File::create(file_path).await?;
        file.write_all(&serialized).await?;
        Ok(())
    }

    pub async fn from_file(file_path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(file_path).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        let entry: LdapEntry = bincode::deserialize(&bytes).unwrap();
        Ok(entry)
    }
}
