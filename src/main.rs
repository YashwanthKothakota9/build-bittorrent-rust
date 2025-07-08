use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use std::{env, fs::File, io::Read};

// Available if you need it!
// use serde_bencode

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
    } else {
        println!("unknown command: {}", args[1])
    }
}
