use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockCipherMut, NewBlockCipher},
    Aes128
};
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::traits::PublicKeyParts;
use std::io::{Error, ErrorKind};

use crate::serializer::IOResult;

pub struct KeyPair {
    pub public: RsaPublicKey,
    pub private: RsaPrivateKey,
    pub nonce: Vec<u8>,
    pub encoded: Vec<u8>
}

impl KeyPair {
    const BITS: usize = 1024;
    const NONCE_SIZE: usize = 4;

    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, Self::BITS)
            .expect("failed to generate a key");
        let public = RsaPublicKey::from(&private);
        let mut nonce = vec![0u8; Self::NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let encoded = rsa_der::public_key_to_der(&public.n().to_bytes_be(), &public.e().to_bytes_be());
        Self { public, private, nonce, encoded }
    }

    pub fn decrypt(&self, data: &[u8]) -> IOResult<Vec<u8>> {
        match self.private.decrypt(Pkcs1v15Encrypt, data) {
            Ok(data) => Ok(data),
            Err(_) => Err(Error::from(ErrorKind::Other))
        }
    }
}

/// https://gist.github.com/RoccoDev/8fa130f1946f89702f799f89b8469bc9?permalink_comment_id=4561673#gistcomment-4561673
pub fn calc_hash(mut hash: [u8; 20]) -> String {
    let negative = (hash[0] & 0x80) == 0x80;

    // Digest is 20 bytes, so 40 hex digits plus the minus sign if necessary.
    let mut hex = String::with_capacity(40 + negative as usize);
    if negative {
        hex.push('-');

        // two's complement
        let mut carry = true;
        for b in hash.iter_mut().rev() {
            (*b, carry) = (!*b).overflowing_add(carry as u8);
        }
    }
    hex.extend(
        hash.into_iter()
            // extract hex digits
            .flat_map(|x| [x >> 4, x & 0xf])
            // skip leading zeroes
            .skip_while(|&x| x == 0)
            .map(|x| char::from_digit(x as u32, 16).expect("x is always valid base16")),
    );
    hex
}

const BYTES_SIZE: usize = 16;

/// https://github.com/Twister915/craftio-rs/blob/master/src/cfb8.rs
pub struct CraftCipher {
    iv: GenericArray<u8, U16>,
    tmp: GenericArray<u8, U16>,
    cipher: Aes128,
}

impl CraftCipher {
    pub fn new(key: &[u8], iv: &[u8]) -> IOResult<Self> {
        if iv.len() != BYTES_SIZE || key.len() != BYTES_SIZE {
            return Err(Error::from(ErrorKind::InvalidData))
        }

        let mut iv_out = [0u8; BYTES_SIZE];
        iv_out.copy_from_slice(iv);

        let mut key_out = [0u8; BYTES_SIZE];
        key_out.copy_from_slice(key);

        let tmp = [0u8; BYTES_SIZE];

        Ok(Self {
            iv: GenericArray::from(iv_out),
            tmp: GenericArray::from(tmp),
            cipher: Aes128::new(&GenericArray::from(key_out)),
        })
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        unsafe { self.crypt(data, false) }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        unsafe { self.crypt(data, true) }
    }

    unsafe fn crypt(&mut self, data: &mut [u8], decrypt: bool) {
        let iv = &mut self.iv;
        const IV_SIZE: usize = 16;
        const IV_SIZE_MINUS_ONE: usize = IV_SIZE - 1;
        let iv_ptr = iv.as_mut_ptr();
        let iv_end_ptr = iv_ptr.offset(IV_SIZE_MINUS_ONE as isize);
        let tmp_ptr = self.tmp.as_mut_ptr();
        let tmp_offset_one_ptr = tmp_ptr.offset(1);
        let cipher = &mut self.cipher;
        let n = data.len();
        let mut data_ptr = data.as_mut_ptr();
        let data_end_ptr = data_ptr.offset(n as isize);

        while data_ptr != data_end_ptr {
            std::ptr::copy_nonoverlapping(iv_ptr, tmp_ptr, IV_SIZE);
            cipher.encrypt_block(iv);
            let orig = *data_ptr;
            let updated = orig ^ *iv_ptr;
            std::ptr::copy_nonoverlapping(tmp_offset_one_ptr, iv_ptr, IV_SIZE_MINUS_ONE);
            if decrypt {
                *iv_end_ptr = orig;
            } else {
                *iv_end_ptr = updated;
            }
            *data_ptr = updated;
            data_ptr = data_ptr.offset(1);
        }
    }
}
