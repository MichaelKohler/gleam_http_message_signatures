//// Ed25519 key material.
////
//// A thin, domain-scoped wrapper over `kryptos/eddsa` fixed to the Ed25519
//// curve, so callers never need to import `kryptos` directly or think about
//// `kryptos/eddsa.Curve`.

import gleam/bit_array
import gleam/result
import kryptos/eddsa

pub type PrivateKey =
  eddsa.PrivateKey

pub type PublicKey =
  eddsa.PublicKey

pub type KeyError {
  InvalidPem
  InvalidBase64
  InvalidKeyBytes
}

/// Generates a new Ed25519 key pair.
pub fn generate() -> #(PrivateKey, PublicKey) {
  eddsa.generate_key_pair(eddsa.Ed25519)
}

/// Loads a private key (and its derived public key) from a PKCS#8 PEM.
pub fn key_pair_from_pem(
  pem: String,
) -> Result(#(PrivateKey, PublicKey), KeyError) {
  eddsa.from_pem(pem)
  |> result.replace_error(InvalidPem)
}

/// Loads a public key from an SPKI PEM.
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, KeyError) {
  eddsa.public_key_from_pem(pem)
  |> result.replace_error(InvalidPem)
}

/// Loads a private key (and its derived public key) from a base64-encoded
/// 32-byte seed — the format Open Payments-style ecosystems commonly use to
/// distribute raw Ed25519 keys.
pub fn key_pair_from_base64(
  seed: String,
) -> Result(#(PrivateKey, PublicKey), KeyError) {
  use bytes <- result.try(
    bit_array.base64_decode(seed) |> result.replace_error(InvalidBase64),
  )
  eddsa.from_bytes(eddsa.Ed25519, bytes)
  |> result.replace_error(InvalidKeyBytes)
}

/// Loads a public key from a base64-encoded 32-byte point.
pub fn public_key_from_base64(bytes: String) -> Result(PublicKey, KeyError) {
  use decoded <- result.try(
    bit_array.base64_decode(bytes) |> result.replace_error(InvalidBase64),
  )
  eddsa.public_key_from_bytes(eddsa.Ed25519, decoded)
  |> result.replace_error(InvalidKeyBytes)
}

/// Exports a private key as a PKCS#8 PEM.
pub fn private_key_to_pem(key: PrivateKey) -> Result(String, KeyError) {
  eddsa.to_pem(key)
  |> result.replace_error(InvalidPem)
}

/// Exports a public key as an SPKI PEM.
pub fn public_key_to_pem(key: PublicKey) -> Result(String, KeyError) {
  eddsa.public_key_to_pem(key)
  |> result.replace_error(InvalidPem)
}
