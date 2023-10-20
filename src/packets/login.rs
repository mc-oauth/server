use crate::serializer::{UUID, VarInt, IOResult, Serializable};
use crate::connection::{C2SPacket, Connection};
use crate::encryption::KeyPair;
use std::io::{Read, Write};

#[derive(Debug)]
pub struct LoginPacket {
    pub name: String,
    pub uuid: Option<UUID>
}

impl LoginPacket {
    pub fn from(client: &mut Connection, protocol: i32) -> IOResult<Self> {
        let mut packet = client.read_packet()?;
        Self::read(&mut packet, protocol)
    }

    pub fn read(packet: &mut C2SPacket, protocol: i32) -> IOResult<Self> {
        let body = &mut packet.body;
        let name = String::deserialize(body)?;

        let mut uuid = None;
        // >= Minecraft 1.19
        if protocol >= 759 && (protocol > 763 || bool::deserialize(body)?) {
            uuid = Some(UUID::deserialize(body)?);
        }

        Ok(Self { name, uuid })
    }
}

#[derive(Debug)]
pub struct C2SEncryptionKeyResponse {
    pub secrect: Vec<u8>,
    pub verify_token: Vec<u8>
}

impl C2SEncryptionKeyResponse {
    pub fn from(client: &mut Connection, key: &KeyPair) -> IOResult<Self> {
        let mut packet = client.read_packet()?;
        Self::read(&mut packet, key)
    }

    pub fn read(packet: &mut C2SPacket, key: &KeyPair) -> IOResult<Self> {
        let body = &mut packet.body;
        // Secrect
        let secrect_len = VarInt::read(body)? as usize;
        let mut secrect = vec![0u8; secrect_len];
        body.read_exact(&mut secrect)?;
        // Token
        let token_len = VarInt::read(body)? as usize;
        let mut verify_token = vec![0u8; token_len];
        body.read_exact(&mut verify_token)?; 
        Ok(Self { 
            secrect: key.decrypt(&secrect)?,
            verify_token: key.decrypt(&verify_token)?
        })
    }
}

pub fn write_encryption_request(key: &KeyPair, connection: &mut Connection) -> IOResult<()> {
    let mut body = Vec::new();
    "".to_string().serialize(&mut body)?; // Server id
    // Public key
    VarInt::write(key.encoded.len() as i32, &mut body)?;
    body.write_all(&key.encoded)?;
    // Verify token
    VarInt::write(key.nonce.len() as i32, &mut body)?;
    body.write_all(&key.nonce)?;
    // Send packet
    connection.write_packet(0x01, &mut body)
}
