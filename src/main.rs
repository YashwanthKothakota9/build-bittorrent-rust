use serde_json::{Map, Value};
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

    format!("Tracker URL: {}\nLength: {}", announce, length)
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
