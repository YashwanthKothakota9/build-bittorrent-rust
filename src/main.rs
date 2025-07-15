use rand::Rng;
use reqwest::blocking;
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use std::{collections::HashMap, env, fs::File, io::Read, io::Write, net::TcpStream};

// Available if you need it!
// use serde_bencode

// Peer message ID constants
const CHOKE_ID: u8 = 0;
const UNCHOKE_ID: u8 = 1;
const INTERESTED_ID: u8 = 2;
const NOT_INTERESTED_ID: u8 = 3;
const HAVE_ID: u8 = 4;
const BITFIELD_ID: u8 = 5;
const REQUEST_ID: u8 = 6;
const PIECE_ID: u8 = 7;

// Struct to represent a peer message
#[derive(Debug)]
struct PeerMessage {
    id: u8,
    payload: Vec<u8>,
}

impl PeerMessage {
    fn new(id: u8, payload: Vec<u8>) -> Self {
        PeerMessage { id, payload }
    }

    // Create a message with empty payload
    fn new_empty(id: u8) -> Self {
        PeerMessage {
            id,
            payload: Vec::new(),
        }
    }
}

// Read a peer message from a TCP stream
// Returns the message or an error if reading fails
fn read_peer_message(stream: &mut TcpStream) -> std::io::Result<PeerMessage> {
    // Read 4-byte message length (big-endian)
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let message_length = u32::from_be_bytes(length_bytes);

    // Handle keep-alive messages (length = 0)
    if message_length == 0 {
        // Keep-alive message has no ID or payload
        // We'll represent this with a special ID (255 is not used in the protocol)
        return Ok(PeerMessage::new(255, Vec::new()));
    }

    // Read message ID (1 byte)
    let mut id_byte = [0u8; 1];
    stream.read_exact(&mut id_byte)?;
    let message_id = id_byte[0];

    // Read payload (remaining bytes)
    let payload_length = message_length - 1; // Subtract 1 for the message ID byte
    let mut payload = vec![0u8; payload_length as usize];
    if payload_length > 0 {
        stream.read_exact(&mut payload)?;
    }

    Ok(PeerMessage::new(message_id, payload))
}

// Write a peer message to a TCP stream
// Returns success or an error if writing fails
fn write_peer_message(stream: &mut TcpStream, message: &PeerMessage) -> std::io::Result<()> {
    // Calculate total message length (ID + payload)
    let message_length = 1 + message.payload.len() as u32;

    // Write 4-byte length prefix (big-endian)
    let length_bytes = message_length.to_be_bytes();
    stream.write_all(&length_bytes)?;

    // Write 1-byte message ID
    stream.write_all(&[message.id])?;

    // Write payload
    if !message.payload.is_empty() {
        stream.write_all(&message.payload)?;
    }

    // Ensure data is sent immediately
    stream.flush()?;

    Ok(())
}

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

fn handshake(file_name: &str, peer_addr: &str) -> String {
    // Parse peer address
    let parts: Vec<&str> = peer_addr.split(':').collect();
    if parts.len() != 2 {
        panic!("Invalid peer address format. Expected IP:PORT");
    }
    let ip = parts[0];
    let port: u16 = parts[1].parse().expect("Invalid port number");

    // Get info hash from torrent file
    let info_hash = get_info_hash_bytes(file_name);

    // Generate random peer ID (20 bytes)
    let mut rng = rand::thread_rng();
    let peer_id: Vec<u8> = (0..20).map(|_| rng.gen()).collect();

    // Build handshake message (68 bytes total)
    let mut handshake_msg = Vec::with_capacity(68);

    // 1 byte: length of protocol string (19)
    handshake_msg.push(19u8);

    // 19 bytes: "BitTorrent protocol"
    handshake_msg.extend_from_slice(b"BitTorrent protocol");

    // 8 bytes: reserved (all zeros)
    handshake_msg.extend_from_slice(&[0u8; 8]);

    // 20 bytes: info hash
    handshake_msg.extend_from_slice(&info_hash);

    // 20 bytes: peer ID
    handshake_msg.extend_from_slice(&peer_id);

    // Connect to peer via TCP
    let mut stream =
        TcpStream::connect(format!("{}:{}", ip, port)).expect("Failed to connect to peer");

    // Send handshake
    stream
        .write_all(&handshake_msg)
        .expect("Failed to send handshake");

    // Receive handshake response (also 68 bytes)
    let mut response = [0u8; 68];
    stream
        .read_exact(&mut response)
        .expect("Failed to receive handshake response");

    // Extract peer ID from response (bytes 48-67)
    let received_peer_id = &response[48..68];

    // Convert to hex and return
    received_peer_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

// Helper function to get torrent metadata needed for piece calculation
fn get_torrent_metadata(file_name: &str) -> (u64, u64) {
    let mut file = File::open(file_name).expect("Failed to open torrent file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");

    let (torrent_val, _) = decode_value_bytes(&bytes);

    let length = torrent_val
        .as_object()
        .and_then(|m| m.get("info"))
        .and_then(|info| info.as_object())
        .and_then(|im| im.get("length"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as u64;

    let piece_length = torrent_val
        .as_object()
        .and_then(|m| m.get("info"))
        .and_then(|info| info.as_object())
        .and_then(|im| im.get("piece length"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as u64;

    (length, piece_length)
}

// Helper function to calculate total number of pieces in the torrent
fn get_total_pieces(file_name: &str) -> usize {
    let (total_length, piece_length) = get_torrent_metadata(file_name);
    // Use ceiling division to get total pieces
    ((total_length + piece_length - 1) / piece_length) as usize
}

// Helper function to get the expected SHA1 hash for a specific piece index
fn get_piece_hash(file_name: &str, piece_index: usize) -> Vec<u8> {
    let mut file = File::open(file_name).expect("Failed to open torrent file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");

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

    // Each piece hash is 20 bytes
    let hash_start = piece_index * 20;
    let hash_end = hash_start + 20;

    if hash_end > pieces_data.len() {
        panic!(
            "Piece index {} out of range (only {} pieces available)",
            piece_index,
            pieces_data.len() / 20
        );
    }

    pieces_data[hash_start..hash_end].to_vec()
}

fn download_piece(torrent_file: &str, piece_index: usize, output_file: &str) {
    // Get list of peers from tracker
    let peers = get_peers(torrent_file);
    if peers.is_empty() {
        panic!("No peers found");
    }

    // Connect to first peer and perform handshake
    let peer_addr = &peers[0];

    // Parse peer address
    let parts: Vec<&str> = peer_addr.split(':').collect();
    if parts.len() != 2 {
        panic!("Invalid peer address format. Expected IP:PORT");
    }
    let ip = parts[0];
    let port: u16 = parts[1].parse().expect("Invalid port number");

    // Get info hash from torrent file
    let info_hash = get_info_hash_bytes(torrent_file);

    // Generate random peer ID (20 bytes)
    let mut rng = rand::thread_rng();
    let peer_id: Vec<u8> = (0..20).map(|_| rng.gen()).collect();

    // Build handshake message (68 bytes total)
    let mut handshake_msg = Vec::with_capacity(68);
    handshake_msg.push(19u8); // length of protocol string
    handshake_msg.extend_from_slice(b"BitTorrent protocol"); // 19 bytes
    handshake_msg.extend_from_slice(&[0u8; 8]); // 8 bytes reserved
    handshake_msg.extend_from_slice(&info_hash); // 20 bytes info hash
    handshake_msg.extend_from_slice(&peer_id); // 20 bytes peer ID

    // Connect to peer via TCP
    let mut stream =
        TcpStream::connect(format!("{}:{}", ip, port)).expect("Failed to connect to peer");

    // Send handshake
    stream
        .write_all(&handshake_msg)
        .expect("Failed to send handshake");

    // Receive handshake response (also 68 bytes)
    let mut response = [0u8; 68];
    stream
        .read_exact(&mut response)
        .expect("Failed to receive handshake response");

    // Read bitfield message from peer
    let bitfield_msg = read_peer_message(&mut stream).expect("Failed to read bitfield message");

    // Verify it's a bitfield message
    if bitfield_msg.id != BITFIELD_ID {
        panic!(
            "Expected bitfield message (ID: {}), got ID: {}",
            BITFIELD_ID, bitfield_msg.id
        );
    }

    // Send interested message to peer
    let interested_msg = PeerMessage::new_empty(INTERESTED_ID);
    write_peer_message(&mut stream, &interested_msg).expect("Failed to send interested message");

    // Wait for unchoke message from peer
    let unchoke_msg = read_peer_message(&mut stream).expect("Failed to read unchoke message");

    // Verify it's an unchoke message
    if unchoke_msg.id != UNCHOKE_ID {
        panic!(
            "Expected unchoke message (ID: {}), got ID: {}",
            UNCHOKE_ID, unchoke_msg.id
        );
    }

    // Calculate how many 16KB blocks are needed for this piece
    let (total_length, piece_length) = get_torrent_metadata(torrent_file);

    // Calculate the actual size of this specific piece
    let total_pieces = (total_length + piece_length - 1) / piece_length; // Round up division
    let this_piece_length = if piece_index == (total_pieces - 1) as usize {
        // Last piece might be smaller
        let remainder = total_length % piece_length;
        if remainder == 0 {
            piece_length
        } else {
            remainder
        }
    } else {
        // Normal piece
        piece_length
    };

    // Calculate blocks (16KB = 16384 bytes each)
    const BLOCK_SIZE: u64 = 16 * 1024; // 16KB
    let num_blocks = (this_piece_length + BLOCK_SIZE - 1) / BLOCK_SIZE; // Round up division

    // Store block information for request messages
    let mut blocks = Vec::new();
    for block_index in 0..num_blocks {
        let begin = block_index * BLOCK_SIZE;
        let length = if block_index == num_blocks - 1 {
            // Last block might be smaller
            this_piece_length - begin
        } else {
            // Normal block
            BLOCK_SIZE
        };
        blocks.push((begin, length));
    }

    // Send request messages for each block

    for (_block_index, (begin, length)) in blocks.iter().enumerate() {
        // Create request message payload (12 bytes total)
        let mut payload = Vec::with_capacity(12);

        // 4 bytes: piece index (big-endian u32)
        payload.extend_from_slice(&(piece_index as u32).to_be_bytes());

        // 4 bytes: begin offset (big-endian u32)
        payload.extend_from_slice(&(*begin as u32).to_be_bytes());

        // 4 bytes: length (big-endian u32)
        payload.extend_from_slice(&(*length as u32).to_be_bytes());

        // Create and send request message
        let request_msg = PeerMessage::new(REQUEST_ID, payload);
        write_peer_message(&mut stream, &request_msg).expect("Failed to send request message");
    }

    // Receive piece messages containing block data
    let mut received_blocks: HashMap<u64, Vec<u8>> = HashMap::new();

    for _block_index in 0..blocks.len() {
        let piece_msg = read_peer_message(&mut stream).expect("Failed to read piece message");

        // Verify it's a piece message
        if piece_msg.id != PIECE_ID {
            panic!(
                "Expected piece message (ID: {}), got ID: {}",
                PIECE_ID, piece_msg.id
            );
        }

        // Parse piece message payload
        if piece_msg.payload.len() < 8 {
            panic!(
                "Piece message payload too short: {} bytes",
                piece_msg.payload.len()
            );
        }

        // Extract fields from payload
        let received_piece_index = u32::from_be_bytes([
            piece_msg.payload[0],
            piece_msg.payload[1],
            piece_msg.payload[2],
            piece_msg.payload[3],
        ]) as usize;

        let received_begin = u32::from_be_bytes([
            piece_msg.payload[4],
            piece_msg.payload[5],
            piece_msg.payload[6],
            piece_msg.payload[7],
        ]) as u64;

        let block_data = &piece_msg.payload[8..];

        // Verify this is the piece we requested
        if received_piece_index != piece_index {
            panic!(
                "Received piece index {} but expected {}",
                received_piece_index, piece_index
            );
        }

        // Store block data by its begin offset
        received_blocks.insert(received_begin, block_data.to_vec());
    }

    // Combine all blocks in correct order to form complete piece
    let total_piece_size: usize = blocks.iter().map(|(_, length)| *length as usize).sum();
    let mut complete_piece = Vec::with_capacity(total_piece_size);

    // Combine blocks in correct order (using original blocks sequence)
    for (_block_index, (begin_offset, expected_length)) in blocks.iter().enumerate() {
        // Retrieve block data from HashMap
        let block_data = received_blocks
            .get(begin_offset)
            .expect(&format!("Missing block data for offset {}", begin_offset));

        // Verify block size matches expectation
        if block_data.len() != *expected_length as usize {
            panic!(
                "Block size mismatch: expected {} bytes, got {} bytes for offset {}",
                expected_length,
                block_data.len(),
                begin_offset
            );
        }

        // Append block data to complete piece
        complete_piece.extend_from_slice(block_data);
    }

    // Verify final piece size
    if complete_piece.len() != total_piece_size {
        panic!(
            "Final piece size mismatch: expected {} bytes, got {} bytes",
            total_piece_size,
            complete_piece.len()
        );
    }

    // Verify piece hash matches torrent file
    let mut hasher = Sha1::new();
    hasher.update(&complete_piece);
    let calculated_hash = hasher.finalize().to_vec();

    let expected_hash = get_piece_hash(torrent_file, piece_index);

    if calculated_hash != expected_hash {
        panic!(
            "Hash mismatch!\nExpected: {}\nCalculated: {}",
            expected_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            calculated_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }

    // Save verified piece to output file
    let mut file = File::create(output_file).expect("Failed to create output file");
    file.write_all(&complete_piece)
        .expect("Failed to write piece data to file");
}

// Modified version of download_piece that returns piece data in memory instead of saving to file
fn download_piece_to_memory(torrent_file: &str, piece_index: usize) -> Vec<u8> {
    // Get list of peers from tracker
    let peers = get_peers(torrent_file);
    if peers.is_empty() {
        panic!("No peers found");
    }

    // Connect to first peer and perform handshake
    let peer_addr = &peers[0];

    // Parse peer address
    let parts: Vec<&str> = peer_addr.split(':').collect();
    if parts.len() != 2 {
        panic!("Invalid peer address format. Expected IP:PORT");
    }
    let ip = parts[0];
    let port: u16 = parts[1].parse().expect("Invalid port number");

    // Get info hash from torrent file
    let info_hash = get_info_hash_bytes(torrent_file);

    // Generate random peer ID (20 bytes)
    let mut rng = rand::thread_rng();
    let peer_id: Vec<u8> = (0..20).map(|_| rng.gen()).collect();

    // Build handshake message (68 bytes total)
    let mut handshake_msg = Vec::with_capacity(68);
    handshake_msg.push(19u8); // length of protocol string
    handshake_msg.extend_from_slice(b"BitTorrent protocol"); // 19 bytes
    handshake_msg.extend_from_slice(&[0u8; 8]); // 8 bytes reserved
    handshake_msg.extend_from_slice(&info_hash); // 20 bytes info hash
    handshake_msg.extend_from_slice(&peer_id); // 20 bytes peer ID

    // Connect to peer via TCP
    let mut stream =
        TcpStream::connect(format!("{}:{}", ip, port)).expect("Failed to connect to peer");

    // Send handshake
    stream
        .write_all(&handshake_msg)
        .expect("Failed to send handshake");

    // Receive handshake response (also 68 bytes)
    let mut response = [0u8; 68];
    stream
        .read_exact(&mut response)
        .expect("Failed to receive handshake response");

    // Read bitfield message from peer
    let bitfield_msg = read_peer_message(&mut stream).expect("Failed to read bitfield message");

    // Verify it's a bitfield message
    if bitfield_msg.id != BITFIELD_ID {
        panic!(
            "Expected bitfield message (ID: {}), got ID: {}",
            BITFIELD_ID, bitfield_msg.id
        );
    }

    // Send interested message to peer
    let interested_msg = PeerMessage::new_empty(INTERESTED_ID);
    write_peer_message(&mut stream, &interested_msg).expect("Failed to send interested message");

    // Wait for unchoke message from peer
    let unchoke_msg = read_peer_message(&mut stream).expect("Failed to read unchoke message");

    // Verify it's an unchoke message
    if unchoke_msg.id != UNCHOKE_ID {
        panic!(
            "Expected unchoke message (ID: {}), got ID: {}",
            UNCHOKE_ID, unchoke_msg.id
        );
    }

    // Calculate how many 16KB blocks are needed for this piece
    let (total_length, piece_length) = get_torrent_metadata(torrent_file);

    // Calculate the actual size of this specific piece
    let total_pieces = (total_length + piece_length - 1) / piece_length; // Round up division
    let this_piece_length = if piece_index == (total_pieces - 1) as usize {
        // Last piece might be smaller
        let remainder = total_length % piece_length;
        if remainder == 0 {
            piece_length
        } else {
            remainder
        }
    } else {
        // Normal piece
        piece_length
    };

    // Calculate blocks (16KB = 16384 bytes each)
    const BLOCK_SIZE: u64 = 16 * 1024; // 16KB
    let num_blocks = (this_piece_length + BLOCK_SIZE - 1) / BLOCK_SIZE; // Round up division

    // Store block information for request messages
    let mut blocks = Vec::new();
    for block_index in 0..num_blocks {
        let begin = block_index * BLOCK_SIZE;
        let length = if block_index == num_blocks - 1 {
            // Last block might be smaller
            this_piece_length - begin
        } else {
            // Normal block
            BLOCK_SIZE
        };
        blocks.push((begin, length));
    }

    // Send request messages for each block
    for (_block_index, (begin, length)) in blocks.iter().enumerate() {
        // Create request message payload (12 bytes total)
        let mut payload = Vec::with_capacity(12);

        // 4 bytes: piece index (big-endian u32)
        payload.extend_from_slice(&(piece_index as u32).to_be_bytes());

        // 4 bytes: begin offset (big-endian u32)
        payload.extend_from_slice(&(*begin as u32).to_be_bytes());

        // 4 bytes: length (big-endian u32)
        payload.extend_from_slice(&(*length as u32).to_be_bytes());

        // Create and send request message
        let request_msg = PeerMessage::new(REQUEST_ID, payload);
        write_peer_message(&mut stream, &request_msg).expect("Failed to send request message");
    }

    // Receive piece messages containing block data
    let mut received_blocks: HashMap<u64, Vec<u8>> = HashMap::new();

    for _block_index in 0..blocks.len() {
        let piece_msg = read_peer_message(&mut stream).expect("Failed to read piece message");

        // Verify it's a piece message
        if piece_msg.id != PIECE_ID {
            panic!(
                "Expected piece message (ID: {}), got ID: {}",
                PIECE_ID, piece_msg.id
            );
        }

        // Parse piece message payload
        if piece_msg.payload.len() < 8 {
            panic!(
                "Piece message payload too short: {} bytes",
                piece_msg.payload.len()
            );
        }

        // Extract fields from payload
        let received_piece_index = u32::from_be_bytes([
            piece_msg.payload[0],
            piece_msg.payload[1],
            piece_msg.payload[2],
            piece_msg.payload[3],
        ]) as usize;

        let received_begin = u32::from_be_bytes([
            piece_msg.payload[4],
            piece_msg.payload[5],
            piece_msg.payload[6],
            piece_msg.payload[7],
        ]) as u64;

        let block_data = &piece_msg.payload[8..];

        // Verify this is the piece we requested
        if received_piece_index != piece_index {
            panic!(
                "Received piece index {} but expected {}",
                received_piece_index, piece_index
            );
        }

        // Store block data by its begin offset
        received_blocks.insert(received_begin, block_data.to_vec());
    }

    // Combine all blocks in correct order to form complete piece
    let total_piece_size: usize = blocks.iter().map(|(_, length)| *length as usize).sum();
    let mut complete_piece = Vec::with_capacity(total_piece_size);

    // Combine blocks in correct order (using original blocks sequence)
    for (_block_index, (begin_offset, expected_length)) in blocks.iter().enumerate() {
        // Retrieve block data from HashMap
        let block_data = received_blocks
            .get(begin_offset)
            .expect(&format!("Missing block data for offset {}", begin_offset));

        // Verify block size matches expectation
        if block_data.len() != *expected_length as usize {
            panic!(
                "Block size mismatch: expected {} bytes, got {} bytes for offset {}",
                expected_length,
                block_data.len(),
                begin_offset
            );
        }

        // Append block data to complete piece
        complete_piece.extend_from_slice(block_data);
    }

    // Verify final piece size
    if complete_piece.len() != total_piece_size {
        panic!(
            "Final piece size mismatch: expected {} bytes, got {} bytes",
            total_piece_size,
            complete_piece.len()
        );
    }

    // Verify piece hash matches torrent file
    let mut hasher = Sha1::new();
    hasher.update(&complete_piece);
    let calculated_hash = hasher.finalize().to_vec();

    let expected_hash = get_piece_hash(torrent_file, piece_index);

    if calculated_hash != expected_hash {
        panic!(
            "Hash mismatch!\nExpected: {}\nCalculated: {}",
            expected_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            calculated_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }

    // Return the verified piece data instead of saving to file
    complete_piece
}

// Function to download all pieces of a torrent file sequentially
fn download_all_pieces(torrent_file: &str) -> Vec<Vec<u8>> {
    let total_pieces = get_total_pieces(torrent_file);
    let mut all_pieces = Vec::with_capacity(total_pieces);

    println!("Downloading {} pieces...", total_pieces);

    for piece_index in 0..total_pieces {
        println!("Downloading piece {} of {}", piece_index + 1, total_pieces);
        let piece_data = download_piece_to_memory(torrent_file, piece_index);
        all_pieces.push(piece_data);
    }

    println!("Successfully downloaded all {} pieces", total_pieces);
    all_pieces
}

// Function to combine all pieces into a single file and write to output path
fn combine_pieces_to_file(pieces: Vec<Vec<u8>>, output_file: &str) {
    println!(
        "Combining {} pieces into file: {}",
        pieces.len(),
        output_file
    );

    // Calculate total file size for progress info
    let total_size: usize = pieces.iter().map(|piece| piece.len()).sum();
    println!("Total file size: {} bytes", total_size);

    // Create output file
    let mut file = File::create(output_file).expect("Failed to create output file");

    // Write each piece to the file in order
    for (index, piece) in pieces.iter().enumerate() {
        file.write_all(piece)
            .expect(&format!("Failed to write piece {} to output file", index));
    }

    // Ensure all data is written to disk
    file.flush().expect("Failed to flush output file");

    println!("Successfully wrote complete file to: {}", output_file);
}

// Main function to download entire torrent file
fn download_file(torrent_file: &str, output_file: &str) {
    println!("Starting download of torrent file: {}", torrent_file);
    println!("Output will be saved to: {}", output_file);

    // Download all pieces to memory
    let all_pieces = download_all_pieces(torrent_file);

    // Combine pieces and write to output file
    combine_pieces_to_file(all_pieces, output_file);

    println!("Download completed successfully!");
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
    } else if command == "handshake" {
        if args.len() < 4 {
            eprintln!("Usage: {} handshake <torrent_file> <peer_ip:port>", args[0]);
            std::process::exit(1);
        }
        let file_name = &args[2];
        let peer_addr = &args[3];
        let peer_id = handshake(file_name, peer_addr);
        println!("Peer ID: {}", peer_id);
    } else if command == "download_piece" {
        if args.len() < 6 {
            eprintln!(
                "Usage: {} download_piece -o <output_file> <torrent_file> <piece_index>",
                args[0]
            );
            std::process::exit(1);
        }

        // Check for -o flag
        if &args[2] != "-o" {
            eprintln!("Expected -o flag, got: {}", args[2]);
            std::process::exit(1);
        }

        let output_file = &args[3];
        let torrent_file = &args[4];
        let piece_index: usize = args[5].parse().expect("Invalid piece index");

        download_piece(torrent_file, piece_index, output_file);
    } else if command == "download" {
        if args.len() < 5 {
            eprintln!(
                "Usage: {} download -o <output_file> <torrent_file>",
                args[0]
            );
            std::process::exit(1);
        }

        // Check for -o flag
        if &args[2] != "-o" {
            eprintln!("Expected -o flag, got: {}", args[2]);
            std::process::exit(1);
        }

        let output_file = &args[3];
        let torrent_file = &args[4];

        download_file(torrent_file, output_file);
    } else {
        println!("unknown command: {}", args[1])
    }
}
