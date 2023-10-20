use std::io::{Read, Write, Error, ErrorKind};
use byteorder::{ReadBytesExt, BigEndian};

const SEGMENT_BITS: i32 = 0x7F;
const CONTINUE_BIT: i32 = 0x80;

pub type IOResult<T> = Result<T, Error>;
pub type Stream = dyn Read;

pub trait Serializable : Sized {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize>;
    fn deserialize(stream: &mut Stream) -> IOResult<Self>;
}

#[derive(Debug)]
pub struct VarInt(pub i32);

impl VarInt {
    pub fn read(stream: &mut Stream) -> IOResult<i32> {
        let mut value = 0;
        let mut position = 0;
        let mut buf = [0u8; 1];
        loop {
            stream.read_exact(&mut buf)?;
            let byte = buf[0] as i32;
            value |= (byte & SEGMENT_BITS) << position;
            if (byte & CONTINUE_BIT) == 0 {
                break;
            }
            position += 7;
            if position >= 32 {
                return Err(Error::new(ErrorKind::Other, "VarInt too big"))?;
            }
        }
        Ok(value)
    }

    pub fn write<T: Write>(mut value: i32, stream: &mut T) -> IOResult<usize> {
        let mut buf = [0u8; 1];
        let mut size = 0_usize;
        loop {
            size += 1;
            if (value & !SEGMENT_BITS) == 0 {
                buf[0] = value as u8;
                stream.write_all(&buf)?;
                break;
            }
            buf[0] = ((value & SEGMENT_BITS) | CONTINUE_BIT) as u8;
            stream.write_all(&buf)?;
            value >>= 7;
        }
        Ok(size)
    }
}

#[derive(Debug)]
pub struct UUID(pub u128);

impl UUID {
    pub fn to_string(&self) -> String {
        format!("{:032x}", u128::from_be(self.0))
    }
}

impl Serializable for VarInt {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        Self::write(self.0, buf)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let value = Self::read(stream)?;
        Ok(VarInt(value))
    }
}

impl Serializable for UUID {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        self.0.serialize(buf)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let value = u128::deserialize(stream)?;
        Ok(Self(value))
    }
}

impl Serializable for String {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        let len = self.len() as i32;
        let bytes = self.as_bytes();
        VarInt::write(len, buf)?;
        buf.write(bytes)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let length = VarInt::read(stream)?;
        let mut buf = vec![0u8; length as usize];
        stream.read_exact(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

impl Serializable for bool {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        buf.push(*self as u8);
        Ok(1)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let mut byte = vec![0u8; 1];
        stream.read_exact(&mut byte)?;
        Ok(byte[0] != 0)
    }
}

impl Serializable for i64 {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        let bytes = self.to_be_bytes();
        buf.write(&bytes)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let value = stream.read_i64::<BigEndian>()?;
        Ok(value)
    }
}

impl Serializable for u16 {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        let bytes = self.to_be_bytes();
        buf.write(&bytes)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        let value = stream.read_u16::<BigEndian>()?;
        Ok(value)
    }
}

impl Serializable for u128 {
    fn serialize(&self, buf: &mut Vec<u8>) -> IOResult<usize> {
        let bytes = self.to_be_bytes();
        buf.write(&bytes)
    }

    fn deserialize(stream: &mut Stream) -> IOResult<Self> {
        stream.read_u128::<BigEndian>()
    }
}
