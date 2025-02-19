// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::util::{xor_block_16, Block16};
use crate::aes256::{DecryptionKey, EncryptionKey};
use core::convert::TryInto;

/// Encrypts a byte slice.
///
/// # Panics
///
/// Panics if the byte slice is not a multiple of the block size (16 bytes).
pub fn cbc_encrypt(key: &EncryptionKey, mut iv: Block16, bytes: &mut [u8]) {
    for block in bytes.chunks_mut(16) {
        let block: &mut Block16 = block.try_into().unwrap();
        xor_block_16(block, &iv);
        key.encrypt_block(block);
        iv = *block;
    }
}

/// Decrypts a byte slice.
///
/// # Panics
///
/// Panics if the byte slice is not a multiple of the block size (16 bytes).
pub fn cbc_decrypt(key: &DecryptionKey, mut iv: Block16, bytes: &mut [u8]) {
    for block in bytes.chunks_mut(16) {
        let block: &mut Block16 = block.try_into().unwrap();
        let tmp = *block;
        key.decrypt_block(block);
        xor_block_16(block, &iv);
        iv = tmp;
    }
}

#[cfg(test)]
mod test {
    use super::super::aes256;
    use super::*;

    #[test]
    fn test_cbc_encrypt_decrypt() {
        // Test that cbc_decrypt is the inverse of cbc_encrypt for a bunch of block values.
        let enc_key = aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let dec_key = aes256::DecryptionKey::new(&enc_key);

        for len in 0..16 {
            let mut blocks: Vec<u8> = vec![0; 16 * len];
            for (i, x) in blocks.iter_mut().enumerate() {
                *x = (16 * len + i) as u8;
            }
            let iv = [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ];
            let expected = blocks.clone();

            cbc_encrypt(&enc_key, iv, &mut blocks);
            cbc_decrypt(&dec_key, iv, &mut blocks);
            assert_eq!(blocks, expected);
        }
    }

    #[test]
    fn test_cbc_encrypt_1block_zero_iv() {
        let key = aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        let iv = [0; 16];
        cbc_encrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        key.encrypt_block(&mut expected);

        assert_eq!(blocks, expected);
    }

    #[test]
    fn test_cbc_decrypt_1block_zero_iv() {
        let key = aes256::DecryptionKey::new(&aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]));

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        let iv = [0; 16];
        cbc_decrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        key.decrypt_block(&mut expected);

        assert_eq!(blocks, expected);
    }

    #[test]
    fn test_cbc_encrypt_1block() {
        let key = aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        let iv = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f,
        ];
        cbc_encrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        xor_block_16(&mut expected, &iv);
        key.encrypt_block(&mut expected);

        assert_eq!(blocks, expected);
    }

    #[test]
    fn test_cbc_decrypt_1block() {
        let key = aes256::DecryptionKey::new(&aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]));

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        let iv = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f,
        ];
        cbc_decrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ];
        key.decrypt_block(&mut expected);
        xor_block_16(&mut expected, &iv);

        assert_eq!(blocks, expected);
    }

    #[test]
    fn test_cbc_encrypt_2blocks() {
        let key = aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let iv = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f,
        ];
        cbc_encrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let (expected0, expected1) = expected.split_at_mut(16);
        let mut expected0: &mut Block16 = expected0.try_into().unwrap();
        let mut expected1: &mut Block16 = expected1.try_into().unwrap();
        xor_block_16(&mut expected0, &iv);
        key.encrypt_block(&mut expected0);
        xor_block_16(&mut expected1, &expected0);
        key.encrypt_block(&mut expected1);

        assert_eq!(blocks, expected);
    }

    #[test]
    fn test_cbc_decrypt_2blocks() {
        let key = aes256::DecryptionKey::new(&aes256::EncryptionKey::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]));

        let mut blocks = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let iv = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f,
        ];
        cbc_decrypt(&key, iv, &mut blocks);

        let mut expected = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x4c, 0x4d, 0x4e, 0x4f,
        ];
        let (expected0, expected1) = expected.split_at_mut(16);
        let mut expected0: &mut Block16 = expected0.try_into().unwrap();
        let mut expected1: &mut Block16 = expected1.try_into().unwrap();
        key.decrypt_block(&mut expected1);
        xor_block_16(&mut expected1, &expected0);
        key.decrypt_block(&mut expected0);
        xor_block_16(&mut expected0, &iv);

        assert_eq!(blocks, expected);
    }
}
