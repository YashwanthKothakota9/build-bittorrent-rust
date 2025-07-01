use serde_json::Value;
use std::env;

// Available if you need it!
// use serde_bencode

fn decode_bencoded_string(src: &str) -> (Value, usize) {
    let colon_index = src.find(':').expect("missing colon in string");
    let len: usize = src[..colon_index].parse().expect("invalid length");
    let start = colon_index + 1;
    let end = start + len;
    let s = &src[start..end];
    (Value::String(s.to_owned()), end)
}

fn decode_bencoded_number(src: &str) -> (Value, usize) {
    let end = src.find('e').expect("missing e in integer");
    let num: i64 = src[1..end].parse().expect("invalid integer");
    (Value::Number(num.into()), end + 1)
}

fn decode_bencoded_list(src: &str) -> (Value, usize) {
    let mut items = Vec::new();
    let mut current_index = 1;
    while src.as_bytes()[current_index] != b'e' {
        let (item, used) = decode_bencoded_value(&src[current_index..]);
        items.push(item);
        current_index += used;
    }
    (Value::Array(items), current_index + 1)
}

fn decode_bencoded_value(src: &str) -> (Value, usize) {
    match src.chars().next().expect("empty input") {
        '0'..='9' => decode_bencoded_string(src),
        'i' => decode_bencoded_number(src),
        'l' => decode_bencoded_list(src),
        _ => panic!("Unhandled encoded value: {}", src),
    }
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
        let (decoded_value, _) = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value);
    } else {
        println!("unknown command: {}", args[1])
    }
}
