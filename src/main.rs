use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufRead, BufReader, Error};
use std::env;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <hash> <dictionary>", args[0]);
        std::process::exit(1);
    }

    let target_hash = args[1].clone();
    let dictionary_path = args[2].clone();

    match crack_password(&target_hash, &dictionary_path) {
        Some(password) => println!("Password found: {}", password),
        None => println!("Password not found"),
    }

    Ok(())
}

fn crack_password(target_hash: &str, dictionary_path: &str) -> Option<String> {
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

        let handle = thread::spawn(move || {
            for password in chunk {
                let hash = hash_password(&password);

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

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    hex::encode(result)
}
