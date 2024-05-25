use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <hash> <dictionary>", args[0]);
        std::process::exit(1);
    }

    let target_hash = &args[1];
    let dictionary_path = &args[2];

    match crack_password(target_hash, dictionary_path) {
        Some(password) => println!("Password found: {}", password),
        None => println!("Password not found"),
    }
}

fn crack_password(target_hash: &str, dictionary_path: &str) -> Option<String> {
    let file = File::open(dictionary_path).expect("Could not open dictionary file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let password = line.expect("Could not read line");
        let hash = hash_password(&password);

        if hash == target_hash {
            return Some(password);
        }
    }

    None
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    hex::encode(result)
}
