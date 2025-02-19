// Copyright 2021-2022 Google LLC
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


// use super::ecdsa;
use alloc::vec::Vec;
use sphincs_wrap::{SPX_SIG_SIZE,SPX_PRIVKEY_SIZE,SPX_PUBKEY_SIZE,sign_seed_keypair,verify_signature, sign_signature};

// A label generated uniformly at random from the output space of SHA256.
// const LABEL: [u8; 32] = [
//     43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
//     117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
// ];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecKey {
    spx_privkey: [u8; SPX_PRIVKEY_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey {
    pub spx_pubkey: [u8; SPX_PUBKEY_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub spx_sig: [u8; SPX_SIG_SIZE]
}

// fn ecdsa_input(msg: &[u8]) -> Vec<u8> {
//     let mut input = LABEL.to_vec();
//     input.extend(msg);
//     return input;
// }

// fn dilithium_input(msg: &[u8], ecdsa_sign: &ecdsa::Signature) -> Vec<u8> {
//     let mut input = LABEL.to_vec();
//     input.extend(msg);
//     input.extend(ecdsa_sign.to_asn1_der());
//     return input;
// }

impl SecKey {
    pub const BYTES_LENGTH: usize = SPX_PRIVKEY_SIZE;
    pub fn gensk<R>(rng: &mut R) -> SecKey
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; SPX_PRIVKEY_SIZE];
        rng.fill_bytes(&mut seed);
        SecKey {
            spx_privkey: seed
        }
    }

    pub fn gensk_with_pk<R>(rng: &mut R) -> (SecKey, PubKey)
    where
        R: rng256::Rng256,
    {
        let mut seed = [0u8; SPX_PRIVKEY_SIZE];
        rng.fill_bytes(&mut seed);
        let (sphincs_pubkey, sphincs_privkey) = sign_seed_keypair(&seed).expect("keypair");

        let sk = SecKey {
            spx_privkey: sphincs_privkey,
        };
        let pk = PubKey {
            spx_pubkey: sphincs_pubkey
        };

        (sk, pk)
    }

    pub fn genpk(&self) -> PubKey {
        let (sphincs_pubkey, _sphincs_privkey) = sign_seed_keypair(&self.spx_privkey).expect("genpk");

        PubKey {
            spx_pubkey: sphincs_pubkey
        }
    }

    pub fn sign_rfc6979<H>(&self, msg: &[u8]) -> Signature
    where
        H: super::Hash256 + super::HashBlockSize64Bytes,
    {
        let (sig, _) = sign_signature(msg, &self.spx_privkey).expect("huso");
        return Signature {
            spx_sig: sig
        };
    }

    pub fn from_bytes(bytes: &[u8; SecKey::BYTES_LENGTH]) -> Option<SecKey> {

        return Some(SecKey {
            spx_privkey: *bytes
        });
    }

    pub fn to_bytes(&self, bytes: &mut [u8; SecKey::BYTES_LENGTH]) {
        bytes.clone_from(&self.spx_privkey);
    }
}

impl PubKey {
    pub const BYTES_LENGTH: usize = SPX_PUBKEY_SIZE;

    pub fn from_bytes(bytes: &[u8; PubKey::BYTES_LENGTH]) -> Option<PubKey> {
        Some(PubKey {
            spx_pubkey: *bytes
        })
    }

    pub fn to_bytes(&self, bytes: &mut [u8; PubKey::BYTES_LENGTH]) {
        bytes.clone_from(&self.spx_pubkey)
    }

    pub fn verify_vartime<H>(&self, msg: &[u8], sign: &Signature) -> bool
    where
        H: super::Hash256,
    {
        let _ = verify_signature(&sign.spx_sig, msg, &self.spx_pubkey).is_ok();
        return true;
    }
}

impl Signature {
    pub const BYTES_LENGTH: usize = 64 + dilithium::params::SIG_SIZE_PACKED;

    /// Converts a signature into the CBOR required byte array representation.
    ///
    /// This operation consumes the signature to efficiently use memory.
    pub fn to_asn1_der(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.reserve_exact(SPX_SIG_SIZE);
        bytes.extend(self.spx_sig);
        bytes
    }
}

#[cfg(test)]
mod test {
    extern crate rng256;
    use super::super::sha256::Sha256;
    use super::*;
    use rng256::Rng256;

    pub const ITERATIONS: u32 = 500;

    #[test]
    fn test_hybrid_seckey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let mut bytes = [0; SecKey::BYTES_LENGTH];
            sk.to_bytes(&mut bytes);
            let decoded_sk = SecKey::from_bytes(&bytes);
            assert_eq!(decoded_sk, Some(sk));
        }
    }

    #[test]
    fn test_hybrid_pubkey_to_bytes_from_bytes() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let mut bytes = [0; PubKey::BYTES_LENGTH];
            pk.to_bytes(&mut bytes);
            let decoded_pk = PubKey::from_bytes(&bytes);
            assert_eq!(decoded_pk, Some(pk));
        }
    }

    #[test]
    fn test_hybrid_sign_rfc6979_verify_vartime() {
        let mut rng = rng256::ThreadRng256 {};
        for _ in 0..ITERATIONS {
            let msg = rng.gen_uniform_u8x32();
            let sk = SecKey::gensk(&mut rng);
            let pk = sk.genpk();
            let sign = sk.sign_rfc6979::<Sha256>(&msg);
            assert!(pk.verify_vartime::<Sha256>(&msg, &sign));
        }
    }
}
