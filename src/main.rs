#[macro_use]
extern crate lazy_static;

use anyhow::{anyhow, Result};
use clap::{App, Arg};
use itertools::Itertools;
use regex::Regex;
use sodiumoxide::crypto::hash;
use sodiumoxide::hex;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

lazy_static! {
    static ref VULNERABLE_JARS: HashSet<String> = {
        let known = include_str!("../vulnerable.sha256");
        let mut hashes = HashSet::new();
        for hash in known.lines().into_iter() {
            hashes.insert(hash.to_string());
        }
        hashes
    };
    static ref VULNERABLE_CLASS: Regex = Regex::new(r".*log4j.*JndiLookup.class$").unwrap();
}

trait Check {
    fn new() -> Self;
    fn run(&self, filename: &str) -> Result<()>;
}

type FileHash = &'static HashSet<String>;
impl Check for FileHash {
    fn new() -> Self {
        &VULNERABLE_JARS
    }

    fn run(&self, filename: &str) -> Result<()> {
        let reader = BufReader::new(File::open(filename)?);
        let mut hash = hash::sha256::State::new();
        reader
            .bytes()
            .chunks(1_024_000)
            .into_iter()
            .for_each(|chunk| {
                let data: Vec<u8> = chunk.map(|x| x.unwrap()).collect();
                hash.update(&data);
            });
        let digest = hash.finalize();
        let hex_digest = hex::encode(digest);
        if self.contains(&hex_digest) {
            Err(anyhow!(
                "matches sha256:{} which is known to be vulnerable to CVE-2021-44228",
                &hex_digest[0..8]
            ))
        } else {
            Ok(())
        }
    }
}

type ClassName = &'static Regex;
impl Check for ClassName {
    fn new() -> Self {
        &VULNERABLE_CLASS
    }

    fn run(&self, filename: &str) -> Result<()> {
        let reader = BufReader::new(File::open(filename)?);
        let jar = zip::ZipArchive::new(reader)?;
        let err = jar
            .file_names()
            .filter(|f| self.is_match(*f))
            .join(", ");
        if err.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "contains the file {} which means it may be vulnerable to CVE-2021-44228",
                err
            ))
        }
    }
}

fn main() -> Result<()> {
    let opts = App::new("CVE-2021-44228 Log4Shell File Detector")
    .version("1.0")
    .author("Grant Murphy <gcmurphy@protonmail.com>")
    .about("Check a JAR file against known vulnerable hashes and the existence of a JndiLookup.class")
    .arg(Arg::with_name("JAR")
        .help("The JAR file to scan")
        .required(true)
        .index(1)
    ).get_matches();

    let filename = opts.value_of("JAR").unwrap();
    if let Err(e) = FileHash::new()
        .run(filename)
        .and_then(|_| ClassName::new().run(filename))
    {
        Err(anyhow!("{} {}", filename, e))
    } else {
        Ok(())
    }
}
