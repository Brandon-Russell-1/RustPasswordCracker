use sha2::{Sha256, Digest as Sha2Digest};
use md5::Md5;
use sha1::{Sha1, Digest as Sha1Digest};
use std::fs::File;
use std::io::{BufRead, BufReader, Error};
use std::env;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone)]
enum HashType {
    Sha256,
    Md5,
    Sha1,
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <hash_type> <hash> <dictionary>", args[0]);
        std::process::exit(1);
    }

    let hash_type = match args[1].as_str() {
        "sha256" => HashType::Sha256,
        "md5" => HashType::Md5,
        "sha1" => HashType::Sha1,
        _ => {
            eprintln!("Unsupported hash type: {}", args[1]);
            std::process::exit(1);
        }
    };

    let target_hash = args[2].clone();
    let dictionary_path = args[3].clone();

    match crack_password(hash_type, &target_hash, &dictionary_path) {
        Some(password) => println!("Password found: {}", password),
        None => println!("Password not found"),
    }

    Ok(())
}

fn crack_password(hash_type: HashType, target_hash: &str, dictionary_path: &str) -> Option<String> {
    let file = match File::open(dictionary_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Could not open dictionary file: {}", e);
            return None;
        }
    };

    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .collect();

    let target_hash = Arc::new(target_hash.to_string());
    let found_password = Arc::new(Mutex::new(None));
    let num_threads = num_cpus::get();
    let chunk_size = (passwords.len() / num_threads) + 1;

    let mut threads = vec![];

    for chunk in passwords.chunks(chunk_size) {
        let target_hash = Arc::clone(&target_hash);
        let found_password = Arc::clone(&found_password);
        let chunk = chunk.to_vec();  // Convert chunk to Vec to own the data in the thread
        let hash_type = hash_type.clone();

        let handle = thread::spawn(move || {
            for password in chunk {
                let hash = hash_password(&hash_type, &password);

                if hash == *target_hash {
                    let mut found = found_password.lock().unwrap();
                    *found = Some(password);
                    break;
                }

                if found_password.lock().unwrap().is_some() {
                    break;
                }
            }
        });

        threads.push(handle);
    }

    for handle in threads {
        handle.join().expect("Thread failed to join");
    }

    let result = found_password.lock().unwrap().clone();
    result
}

fn hash_password(hash_type: &HashType, password: &str) -> String {
    match hash_type {
        HashType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(password);
            let result = hasher.finalize();
            hex::encode(result)
        },
        HashType::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(password);
            let result = hasher.finalize();
            hex::encode(result)
        },
        HashType::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(password);
            let result = hasher.finalize();
            hex::encode(result)
        },
    }
}
