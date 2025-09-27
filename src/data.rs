use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LdapEntry {
    dn: String,
    attributes: Vec<Attribute>,
}

#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Attribute {
    key: String,
    value: Vec<String>,
}

impl LdapEntry {
    fn new(dn: String, attributes: Vec<Attribute>) -> Self {
        LdapEntry { dn, attributes }
    }

    pub async fn to_file(&self, file_path: &Path) -> std::io::Result<()> {
        let serialized = bincode::encode_to_vec(self, bincode::config::standard()).unwrap();
        let mut file = File::create(file_path).await?;
        file.write_all(&serialized).await?;
        Ok(())
    }

    pub async fn from_file(file_path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(file_path).await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await?;
        let (entry, _): (LdapEntry, usize) = bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        Ok(entry)
    }
}

async fn save_ldap_entry(entry: &LdapEntry) -> std::io::Result<()> {
    let path = dn_to_path(&entry.dn).await;
    fs::create_dir_all(path.parent().unwrap()).await?;
    entry.to_file(&path).await
}

async fn load_ldap_entry(dn: &str) -> std::io::Result<LdapEntry> {
    let path = dn_to_path(dn).await;
    LdapEntry::from_file(&path).await
}

async fn dn_to_path(dn: &str) -> PathBuf {
    let components: Vec<&str> = dn.split(',').collect();
    let mut path = PathBuf::new();
    for component in components.iter().rev() {
        let key_value: Vec<&str> = component.split('=').collect();
        let (key, value) = (key_value[0], key_value[1]);
        path.push(format!("{}={}", key, value));
    }
    path.push("entry.bson");
    path
}
