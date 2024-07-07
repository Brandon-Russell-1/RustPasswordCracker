use sha2::{Sha256, Digest as Sha2Digest};
use md5::Md5;
use sha1::{Sha1, Digest as Sha1Digest};
use std::env;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use reqwest::Client;
use tokio;
use std::error::Error;
use serde::Deserialize;

#[derive(Clone)]
enum HashType {
    Sha256,
    Md5,
    Sha1,
}

#[derive(Deserialize)]
struct Config {
    openai: OpenAIConfig,
}

#[derive(Deserialize)]
struct OpenAIConfig {
    api_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("Usage: {} <hash_type> <hash> <start_letters> <case> <length> <total_words>", args[0]);
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
    let start_letters = &args[3];
    let case = &args[4];
    let length = &args[5];
    let total_words: usize = args[6].parse().unwrap_or(1000);

    let config = read_config("config.toml")?;
    let passwords = get_passwords_from_openai(&config.openai.api_key, start_letters, case, length, total_words).await?;
    println!("Number of passwords generated: {}", passwords.len()); // Print number of passwords

    match crack_password(hash_type, &target_hash, &passwords) {
        Some(password) => println!("Password found: {}", password),
        None => println!("Password not found"),
    }

    Ok(())
}

fn read_config(filename: &str) -> Result<Config, Box<dyn Error>> {
    let contents = fs::read_to_string(filename)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

async fn get_passwords_from_openai(api_key: &str, start_letters: &str, case: &str, length: &str, total_words: usize) -> Result<Vec<String>, Box<dyn Error>> {
    let client = Client::new();
    let request_url = "https://api.openai.com/v1/chat/completions";

    let prompt = format!(
        "Make a custom word list, starting with the letters '{}', in '{}', and '{}' characters long, {} words in total. Make the entire {} word list here no matter what. Don't number the list.",
        start_letters, case, length, total_words, total_words
    );

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert and educational professional."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 4096, // Increased token limit to handle larger responses
    });

    println!("Sending request to URL: {}", request_url);
    println!("Request body: {}", request_body);

    let response = client.post(request_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    println!("Response status: {}", response.status());
    println!("Response headers: {:?}", response.headers());

    if !response.status().is_success() {
        eprintln!("Failed to fetch passwords: {}", response.status());
        let response_text = response.text().await?;
        eprintln!("Response body: {}", response_text);
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to fetch passwords")));
    }

    let response_json = response.json::<serde_json::Value>().await?;
    println!("Response JSON: {:?}", response_json); // Debugging line to print the JSON response

    let text = match response_json["choices"][0]["message"]["content"].as_str() {
        Some(text) => text,
        None => {
            eprintln!("Failed to parse the response JSON");
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse the response JSON")));
        }
    };

    let passwords: Vec<String> = text.lines().map(|line| line.trim().to_string()).collect();
    Ok(passwords)
}

fn crack_password(hash_type: HashType, target_hash: &str, passwords: &[String]) -> Option<String> {
    let target_hash = Arc::new(target_hash.to_string());
    let found_password = Arc::new(Mutex::new(None));
    let num_threads = num_cpus::get();
    let chunk_size = (passwords.len() / num_threads) + 1;

    let mut threads = vec![];

    for chunk in passwords.chunks(chunk_size) {
        let target_hash = Arc::clone(&target_hash);
        let found_password = Arc::clone(&found_password);
        let chunk = chunk.to_vec();
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
