use crate::{connection::{C2SPacket, Connection}, serializer::{IOResult, VarInt, Serializable}};
use std::io::{Error, ErrorKind};

#[derive(Debug, PartialEq)]
pub enum ConnectionState {
    Status,
    Login
}

#[derive(Debug)]
pub struct HandshakePacket {
    pub protocol: i32,
    pub host: String,
    pub port: u16,
    pub next_state: ConnectionState
}

#[derive(Debug)]
pub struct PingRequest {
    pub payload: i64
}

impl HandshakePacket {
    pub fn from(client: &mut Connection) -> IOResult<Self> {
        let mut packet = client.read_packet()?;
        Self::read(&mut packet)
    }

    pub fn read(packet: &mut C2SPacket) -> IOResult<Self> {
        if packet.id != 0x00 {
            return Err(Error::from(ErrorKind::InvalidData))
        }
        let body = &mut packet.body;
        let protocol = VarInt::read(body)?;
        let host = String::deserialize(body)?;
        let port = u16::deserialize(body)?;
        let state = VarInt::read(body)?;
        let next_state = match state {
            1 => ConnectionState::Status,
            2 => ConnectionState::Login,
            _ => return Err(Error::from(ErrorKind::InvalidData))
        };
        Ok(Self { protocol, host, port, next_state })
    }
}

////////////////////////// Ping request ////////////////////////// 

impl PingRequest {
    pub fn from(client: &mut Connection) -> IOResult<Self> {
        let mut packet = client.read_packet()?;
        Self::read(&mut packet)
    }

    pub fn read(packet: &mut C2SPacket) -> IOResult<Self> {
        if packet.id != 0x01 {
            return Err(Error::from(ErrorKind::InvalidData))
        }
        let body = &mut packet.body;
        let payload = i64::deserialize(body)?;
        Ok(Self { payload })
    }
}

impl PingRequest {
    pub fn write(&self, client: &mut Connection) -> IOResult<()> {
        let mut buf = Vec::new();
        self.payload.serialize(&mut buf)?;
        client.write_packet(0x01, &mut buf)
    }
}
