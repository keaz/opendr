use ldap_parser::asn1_rs::Length;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

type Key = u64; // For simplicity, we use i32 as the key type.
type Value = usize;

#[derive(Serialize, Deserialize)]
struct BTreeNode {
    keys: Vec<Key>,
    values: Vec<Value>,
    children: Vec<Option<Box<BTreeNode>>>,
    leaf: bool,
}

impl BTreeNode {
    fn new(t: usize, leaf: bool) -> Self {
        BTreeNode {
            keys: Vec::with_capacity(2 * t - 1),
            values: Vec::with_capacity(2 * t - 1),
            children: Vec::with_capacity(2 * t),
            leaf,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BTree {
    root: Option<Box<BTreeNode>>,
    t: usize,
}

impl BTree {
    fn new(t: usize) -> Self {
        BTree { root: None, t }
    }
}

impl BTreeNode {
    fn search(&self, key: Key) -> Option<&Value> {
        let mut i = 0;
        while i < self.keys.len() && key > self.keys[i] {
            i += 1;
        }
        if i < self.keys.len() && key == self.keys[i] {
            return Some(&self.values[i]);
        }
        if self.leaf {
            None
        } else {
            return self.children[i].as_ref().unwrap().search(key);
        }
    }
}

impl BTree {
    pub fn search(&self, key: Key) -> Option<&Value> {
        match &self.root {
            Some(root) => root.search(key),
            None => None,
        }
    }
}

impl BTreeNode {
    fn split_child(&mut self, i: usize, t: usize) {
        let mut z = BTreeNode::new(t, self.children[i].as_ref().unwrap().leaf);
        let mut y = self.children[i].take().unwrap();

        z.keys = y.keys.split_off(t);
        if !y.leaf {
            z.children = y.children.split_off(t);
        }

        self.children.insert(i + 1, Some(Box::new(z)));
        self.keys.insert(i, y.keys.remove(t - 1));
        self.values.insert(i, y.values.remove(t - 1));
        self.children[i] = Some(y);
    }

    fn insert_non_full(&mut self, key: Key, value: Value, t: usize) {
        let mut i = self.keys.len();
        if self.leaf {
            self.keys.push(key);
            self.values.push(value);
            while i > 0 && self.keys[i] < self.keys[i - 1] {
                self.keys.swap(i, i - 1);
                self.values.swap(i, i - 1);
                i -= 1;
            }
        } else {
            while i > 0 && key < self.keys[i - 1] {
                i -= 1;
            }
            if self.children[i].as_ref().unwrap().keys.len() == 2 * t - 1 {
                self.split_child(i, t);
                if key > self.keys[i] {
                    i += 1;
                }
            }
            self.children[i]
                .as_mut()
                .unwrap()
                .insert_non_full(key, value, t);
        }
    }
}

impl BTree {
    pub fn insert(&mut self, key: Key, value: Value) {
        if self.root.is_none() {
            let mut root = BTreeNode::new(self.t, true);
            root.keys.push(key);
            root.values.push(value);
            self.root = Some(Box::new(root));
        } else {
            let root = self.root.as_mut().unwrap();
            if root.keys.len() == 2 * self.t - 1 {
                let mut s = BTreeNode::new(self.t, false);
                s.children.push(self.root.take());
                s.split_child(0, self.t);
                s.insert_non_full(key, value, self.t);
                self.root = Some(Box::new(s));
            } else {
                root.insert_non_full(key, value, self.t);
            }
        }
    }
}

impl BTree {
    pub async fn save(&self, file_name: &str) -> io::Result<()> {
        let mut file = File::create(file_name).await?;
        let serialized = bincode::serialize(self).unwrap();
        file.write_all(&serialized).await?;

        Ok(())
    }

    pub async fn load_from_file(filename: &str) -> io::Result<Self> {
        let mut file = File::open(filename).await?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).await?;
        let tree: BTree = bincode::deserialize(&buffer).unwrap();
        Ok(tree)
    }
}
