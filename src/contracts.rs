#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![deny(clippy, clippy_pedantic)]
#![allow(missing_docs_in_private_items, unknown_lints)]

extern crate serde;
extern crate serde_json;
extern crate glob;
extern crate futures;

use self::glob::glob;
use self::serde_json::Value;
use std::fs::File;
use std::path::Path;

/// Contracts Service
pub struct Contracts {
    dir: String,
}

impl Contracts {
    /// Initialize new contracts service for a dir
    pub fn new(dir: String) -> Contracts {
        Contracts { dir: dir }
    }

    fn read_json(path: &Path) -> Result<Value, ()> {
        match File::open(path) {
            Ok(f) => serde_json::from_reader(f).or(Err(())),
            Err(_) => Err(()),
        }
    }

    /// List all available contracts
    pub fn list(&self) -> Vec<Value> {
        let files = glob(&format!("{}/*.json", &self.dir)).unwrap();
        files.filter(|x| x.is_ok())
            .map(|x| Contracts::read_json(x.unwrap().as_path()))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    }
}
