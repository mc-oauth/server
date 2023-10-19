use std::io::{Write, Read, Cursor};
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use crate::encryption::CraftCipher;
use crate::serializer::{VarInt, IOResult};

pub type PacketBuffer = Cursor<Vec<u8>>;

pub struct Connection {
    stream: TcpStream,
    pub addr: SocketAddr,
    cipher: Option<CraftCipher>
}

pub struct C2SPacket {
    pub size: i32,
    pub id: i32,
    pub body: PacketBuffer
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr) -> IOResult<Self> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self { stream, addr, cipher: None })
    }

    pub fn close(&mut self) -> IOResult<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    pub fn set_cipher(&mut self, cipher: CraftCipher) {
        self.cipher = Some(cipher);
    }

    fn write(&mut self, buf: &mut [u8]) -> IOResult<()> {
        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(buf);
        }
        self.stream.write_all(buf)
    }

    fn read(&mut self, buf: &mut [u8]) -> IOResult<()> {
        if let Some(cipher) = &mut self.cipher {
            cipher.decrypt(buf);
        }
        self.stream.read_exact(buf)
    }

    pub fn read_byte(&mut self) -> IOResult<u8> {
        let mut buf = [0u8; 1];
        self.read(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_packet(&mut self) -> IOResult<C2SPacket> {
        let size = VarInt::read(&mut self.stream)?;
        let mut buffer = vec![0u8; size as usize];
        self.read(&mut buffer)?;
        let mut body = Cursor::new(buffer);
        let id = VarInt::read(&mut body)?;
        Ok(C2SPacket { size, id, body })
    }

    pub fn write_packet(&mut self, id: i32, buf: &mut [u8]) -> IOResult<()> {
        // Header { packet size, packet id } + body
        let mut id_buf = Vec::new();
        VarInt::write(id, &mut id_buf)?;
        let mut size_buf = Vec::new();
        VarInt::write((id_buf.len() + buf.len()) as i32, &mut size_buf)?;
        // Write to client
        self.write(&mut size_buf)?;
        self.write(&mut id_buf)?;
        self.write(buf)
    }
}
