use std::io::{ErrorKind, Error, Read, Write};
use std::net::TcpListener;
use authentify::connection::Connection;
use authentify::packets::handshake::{HandshakePacket, ConnectionState, PingRequest};
use authentify::packets::login::{LoginPacket, write_encryption_request, C2SEncryptionKeyResponse};
use authentify::serializer::{IOResult, Serializable};
use authentify::store::{Store, Profile};

use crypto::sha1::Sha1;
use crypto::digest::Digest;
use std::env;
use authentify::encryption::{CraftCipher, KeyPair, calc_hash};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let store = Arc::new(Mutex::new(Store::new()));
    let handle = Arc::clone(&store);
    let _server_thread = thread::spawn(move || {
        let result = web_server::run(handle, "0.0.0.0:8080");
        if let Err(err) = result {
            println!("[Http] An error occured: {:?}", err);
        }
    });
    // Run minecraft server
    let result = run(Arc::clone(&store), "0.0.0.0:25565");
    if let Err(err) = result {
        println!("[Minecraft] A fatal error occured: {:?}", err);
    }
}

mod web_server {
    use std::{net::TcpStream, time::Duration};

    use super::*;

    pub fn run(store: Arc<Mutex<Store>>, bind: &str) -> IOResult<()> {
        let listener = TcpListener::bind(bind)?;
        println!("[http] Listening on address {bind}");
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("[http] Could not accept client: {:?}", err);
                    continue;
                }
            };
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let result = on_client(&store, &mut stream);
            if let Err(err) = result {
                eprintln!("[http] Error in client {:?}", err);
            }
            stream.shutdown(std::net::Shutdown::Both)?;
        }
    }

    #[allow(clippy::unused_io_amount)]
    fn on_client(store: &Arc<Mutex<Store>>, stream: &mut TcpStream) -> IOResult<()> {
        let mut buffer = [0; 1024];
        stream.read(&mut buffer)?;
        
        let path = "GET /token/";
        // Check if we get the correct path
        if &buffer[0..path.len()] == path.as_bytes() {
            let token_len = 6_usize;
            let path_len = path.len();
            let slice = &buffer[path_len..path_len + token_len];
            let token = read_number(slice)?;
            // Read profile from store
            let mut data = store.lock().expect("mutex lock failed");
            let profile: Option<Profile> = data.lookup(token);
            drop(data);
            if let Some(profile) = profile {
                let json = serde_json::to_string(&profile)?;
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")?;
                stream.write_all(json.as_bytes())?;
                return stream.write_all(b"\r\n")
            }
        }
        stream.write_all(b"HTTP/1.1 404\r\n\r\n")
    }

    fn read_number(slice: &[u8]) -> IOResult<i32> {
        let mut result = 0;
        for &byte in slice {
            if !(48..=57).contains(&byte) {
                return Err(Error::from(ErrorKind::InvalidInput))
            }
            let digit = (byte - 48) as i32;
            result = result * 10 + digit;
        }
        Ok(result)
    }
}

fn run(store: Arc<Mutex<Store>>, bind: &str) -> IOResult<()> {
    let listener = TcpListener::bind(bind)?;
    println!("[Minecraft] Listening on address {bind}");
    loop {
        let connection = match listener.accept() {
            Ok((stream, addr)) => Connection::new(stream, addr)?,
            Err(err) => {
                println!("Could not accept client: {:?}", err);
                continue;
            }
        };
        let clone = store.clone();
        let _handle = thread::spawn(move || {
            on_client(connection, clone);
        });
    }
}

fn on_client(mut connection: Connection, store: Arc<Mutex<Store>>) {
    let addr = connection.addr.to_string();
    let result = handle(&mut connection, store);
    if let Err(err) = result {
        match err.kind() {
            ErrorKind::WouldBlock => (),
            ErrorKind::UnexpectedEof => (),
            ErrorKind::ConnectionReset => (),
            ErrorKind::NotConnected => (),
            _ => eprintln!("[Minecraft] A fatal error occured: {:?}", err)
        };
    }
    if let Err(err) = connection.close() {
        eprintln!("[{}] An error closing a connection: {:?}", addr, err);
    }
}

fn handle(connection: &mut Connection, store: Arc<Mutex<Store>>) -> IOResult<()> {
    let handshake = HandshakePacket::from(connection)?;
    if handshake.protocol < 47 || (handshake.protocol >= 759 && handshake.protocol <= 760) {
        return Err(Error::new(ErrorKind::Other, "Unsupported protocol version"));
    }
    // Status
    if handshake.next_state == ConnectionState::Status {
        let packet = connection.read_packet()?;
        if packet.id != 0x00 {
            return Err(Error::new(ErrorKind::Other, "Expected packet id 0x00"));
        }
        // Status request
        let json = json!(
            {
                "version": {
                    "name": "AuthServer",
                    "protocol": handshake.protocol
                },
                "players": {
                    "max": 1,
                    "online": 0
                },
                "description": {
                    "text": "§6Join to get an auth code\n§aPowered by auth.aristois.net"
                },
                "enforcesSecureChat": true,
                "previewsChat": true
            }
        ).to_string();
        let mut body = Vec::new();
        json.serialize(&mut body)?;
        connection.write_packet(0x00, &mut body)?;
        // Ping packet
        let packet = PingRequest::from(connection)?;
        return packet.write(connection)
    }
    // C -> S: Login Start
    let login_packet = LoginPacket::from(connection, handshake.protocol)?;
    // S -> C: Encryption Request
    let key_pair = KeyPair::new();
    write_encryption_request(&key_pair, connection)?;
    // C -> S: Encryption key response
    let encryption_response = C2SEncryptionKeyResponse::from(connection, &key_pair)?;
    if key_pair.nonce != encryption_response.verify_token {
        return Err(Error::new(ErrorKind::Other, "Nonce from client does not match expected"));
    }
    let secrect = &encryption_response.secrect;
    let cipher = CraftCipher::new(secrect, secrect)?;
    connection.set_cipher(cipher);

    let hash = hash(&key_pair, secrect);
    // Check if player has joined
    let url = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", login_packet.name, hash);
    let response = match minreq::get(&url).send() {
        Ok(data) => data,
        Err(_) => {
            connection.error()?;
            return Err(Error::new(ErrorKind::Other, "Unable to contact mojang sessionserver"))
        }
    };
    if response.status_code != 200 {
        connection.error()?;
        return Err(Error::new(ErrorKind::Other, "Failed to authenticate user"))
    }
    let data = response.as_bytes();
    let json = serde_json::from_slice::<Value>(data)?;
    let profile = Profile::from_json(&json)?;
    // Generate token
    let mut data = store.lock().expect("mutex lock failed");
    let token = data.generate(profile);
    drop(data);
    println!("[{} -> {}] Provided {} with token {token}", connection.addr, handshake.host, login_packet.name);
    // S -> C: Disconnect
    let json = json!(
        {
            "text": "Your auth code is ",
            "color": "gray",
            "extra": [
                {
                    "color": "red",
                    "bold": true,
                    "text": token.to_string()
                },
                {
                    "text": "\n\n"
                },
                {
                    "text": "This token will expire in ",
                    "extra": [
                        {
                            "text": "5 minutes",
                            "color": "red",
                            "bold": true
                        }
                    ]
                },
                {
                    "text": "\n"
                },
                {
                    "text": "Powered by ",
                    "extra": [
                        {
                            "text": "auth.aristois.net",
                            "color": "red",
                            "bold": true
                        }
                    ]
                }
            ]
        }
    );
    connection.disconnect(&json)
}

fn hash(key_pair: &KeyPair, secrect: &[u8]) -> String {
    let mut sha = Sha1::new();
    sha.input(secrect);
    sha.input(&key_pair.encoded);
    let mut digest = [0u8; 20];
    sha.result(&mut digest);
    calc_hash(digest)
}
