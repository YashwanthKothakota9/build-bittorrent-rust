use reqwest::blocking;
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use std::{env, fs::File, io::Read};

// Available if you need it!
// use serde_bencode

fn url_encode_bytes(bytes: &[u8]) -> String {
    let mut result = String::new();
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

fn parse_usize(bytes: &[u8]) -> (usize, usize) {
    let mut num: usize = 0;
    let mut idx = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        num = num * 10 + (bytes[idx] - b'0') as usize;
        idx += 1;
    }
    (num, idx)
}

fn decode_string_bytes(src: &[u8]) -> (Value, usize) {
    let (len, digits) = parse_usize(src);
    let start = digits + 1;
    let end = start + len;
    let slice = &src[start..end];
    let s = String::from_utf8_lossy(slice).into_owned();
    (Value::String(s), end)
}

fn decode_number_bytes(src: &[u8]) -> (Value, usize) {
    let mut idx = 1;
    let neg = if src[idx] == b'-' {
        idx += 1;
        true
    } else {
        false
    };
    let (num, digits) = parse_usize(&src[idx..]);
    idx += digits;

    let mut num_i64 = num as i64;
    if neg {
        num_i64 = -num_i64;
    }
    (Value::Number(num_i64.into()), idx + 1)
}

fn decode_list_bytes(src: &[u8]) -> (Value, usize) {
    let mut items = Vec::new();
    let mut idx = 1;
    while src[idx] != b'e' {
        let (val, used) = decode_value_bytes(&src[idx..]);
        items.push(val);
        idx += used;
    }
    (Value::Array(items), idx + 1)
}

fn decode_dict_bytes(src: &[u8]) -> (Value, usize) {
    let mut map: Map<String, Value> = Map::new();
    let mut idx = 1;
    while src[idx] != b'e' {
        let (key_val, used_key) = decode_string_bytes(&src[idx..]);
        idx += used_key;
        let key = match key_val {
            Value::String(s) => s,
            _ => unreachable!(),
        };
        let (val, used_val) = decode_value_bytes(&src[idx..]);
        idx += used_val;
        map.insert(key, val);
    }
    (Value::Object(map), idx + 1)
}

fn decode_value_bytes(src: &[u8]) -> (Value, usize) {
    match src[0] {
        b'0'..=b'9' => decode_string_bytes(src),
        b'i' => decode_number_bytes(src),
        b'l' => decode_list_bytes(src),
        b'd' => decode_dict_bytes(src),
        other => panic!("unsupported type byte: {}", other as char),
    }
}

fn get_file_info(file_name: &str) -> String {
    let mut file = File::open(file_name).expect("Failed to open torrent file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");

    let (torrent_val, _) = decode_value_bytes(&bytes);

    let announce = torrent_val
        .as_object()
        .and_then(|m| m.get("announce"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    let length = torrent_val
        .as_object()
        .and_then(|m| m.get("info"))
        .and_then(|info| info.as_object())
        .and_then(|im| im.get("length"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let piece_length = torrent_val
        .as_object()
        .and_then(|m| m.get("info"))
        .and_then(|info| info.as_object())
        .and_then(|im| im.get("piece length"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    // Extract raw pieces bytes directly from the torrent file
    let pieces_tag = b"6:pieces";
    let pieces_pos = bytes
        .windows(pieces_tag.len())
        .position(|w| w == pieces_tag)
        .expect("pieces field not found in .torrent file");

    let pieces_value_start = pieces_pos + pieces_tag.len();
    let (pieces_len, len_digits) = parse_usize(&bytes[pieces_value_start..]);
    let pieces_data_start = pieces_value_start + len_digits + 1; // +1 for the ':'
    let pieces_data = &bytes[pieces_data_start..pieces_data_start + pieces_len];

    let piece_hashes = pieces_data
        .chunks(20)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect::<Vec<_>>();

    let tag = b"4:info";
    let key_pos = bytes
        .windows(tag.len())
        .position(|w| w == tag)
        .expect("indo dict not found in .torrent file");

    let val_start = key_pos + tag.len();
    let (_, val_len) = decode_value_bytes(&bytes[val_start..]);
    let info_bytes = &bytes[val_start..val_start + val_len];

    let mut hasher = Sha1::new();
    hasher.update(info_bytes);
    let info_hash = hasher.finalize();

    format!(
        "Tracker URL: {}\nLength: {}\nInfo Hash: {:x}\nPiece Length: {}\nPiece Hashes:\n{}",
        announce,
        length,
        info_hash,
        piece_length,
        piece_hashes.join("\n")
    )
}

fn get_info_hash_bytes(file_name: &str) -> Vec<u8> {
    let mut file = File::open(file_name).expect("Failed to open torrent file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");

    let tag = b"4:info";
    let key_pos = bytes
        .windows(tag.len())
        .position(|w| w == tag)
        .expect("info dict not found in .torrent file");

    let val_start = key_pos + tag.len();
    let (_, val_len) = decode_value_bytes(&bytes[val_start..]);
    let info_bytes = &bytes[val_start..val_start + val_len];

    let mut hasher = Sha1::new();
    hasher.update(info_bytes);
    hasher.finalize().to_vec()
}

fn get_peers(file_name: &str) -> Vec<String> {
    // Extract torrent info
    let mut file = File::open(file_name).expect("Failed to open torrent file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");

    let (torrent_val, _) = decode_value_bytes(&bytes);

    let announce = torrent_val
        .as_object()
        .and_then(|m| m.get("announce"))
        .and_then(|v| v.as_str())
        .expect("Failed to get announce URL");

    let length = torrent_val
        .as_object()
        .and_then(|m| m.get("info"))
        .and_then(|info| info.as_object())
        .and_then(|im| im.get("length"))
        .and_then(|v| v.as_i64())
        .expect("Failed to get file length") as usize;

    // Get info hash as raw bytes
    let info_hash = get_info_hash_bytes(file_name);

    // URL encode the info hash
    let info_hash_encoded = url_encode_bytes(&info_hash);

    // Build query parameters
    let query_params = [
        ("info_hash", info_hash_encoded.to_string()),
        ("peer_id", "00112233445566778899".to_string()),
        ("port", "6881".to_string()),
        ("uploaded", "0".to_string()),
        ("downloaded", "0".to_string()),
        ("left", length.to_string()),
        ("compact", "1".to_string()),
    ];

    // Build full URL with query parameters
    let mut url = announce.to_string();
    url.push('?');
    for (i, (key, value)) in query_params.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&format!("{}={}", key, value));
    }

    // Make HTTP request
    let response = blocking::get(&url).expect("Failed to make HTTP request");
    let response_bytes = response.bytes().expect("Failed to get response bytes");

    // Extract raw peers bytes directly from the bencoded response
    let peers_tag = b"5:peers";
    let peers_pos = response_bytes
        .windows(peers_tag.len())
        .position(|w| w == peers_tag)
        .expect("peers field not found in tracker response");

    let peers_value_start = peers_pos + peers_tag.len();
    let (peers_len, len_digits) = parse_usize(&response_bytes[peers_value_start..]);
    let peers_data_start = peers_value_start + len_digits + 1; // +1 for the ':'
    let peers_data = &response_bytes[peers_data_start..peers_data_start + peers_len];

    // Convert peers data to IP:PORT format
    let mut peers = Vec::new();

    for chunk in peers_data.chunks(6) {
        if chunk.len() == 6 {
            let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
            let port = ((chunk[4] as u16) << 8) | (chunk[5] as u16);
            peers.push(format!("{}:{}", ip, port));
        }
    }

    peers
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} decode <bencoded_value>", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let (decoded_value, _) = decode_value_bytes(encoded_value.as_bytes());
        println!("{}", decoded_value);
    } else if command == "info" {
        let file_name = &args[2];
        let file_info = get_file_info(file_name);
        println!("{}", file_info);
    } else if command == "peers" {
        let file_name = &args[2];
        let peers = get_peers(file_name);
        for peer in peers {
            println!("{}", peer);
        }
    } else {
        println!("unknown command: {}", args[1])
    }
}
