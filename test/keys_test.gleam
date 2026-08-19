import gleam/bit_array
import http_message_signatures/keys
import kryptos/eddsa

const test_key_public_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----"

const test_key_private_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----"

pub fn generate_produces_a_working_key_pair_test() {
  let #(private_key, public_key) = keys.generate()
  let message = <<"hello world":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert eddsa.verify(public_key, message, signature)
}

pub fn key_pair_from_pem_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let message = <<"hello world":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert eddsa.verify(public_key, message, signature)
}

pub fn public_key_from_pem_test() {
  let assert Ok(_) = keys.public_key_from_pem(test_key_public_pem)
}

pub fn public_key_from_pem_invalid_test() {
  assert keys.public_key_from_pem("not a pem") == Error(keys.InvalidPem)
}

pub fn key_pair_from_base64_round_trip_test() {
  let #(private_key, _public_key) = keys.generate()
  let seed = bit_array.base64_encode(eddsa.to_bytes(private_key), True)

  let assert Ok(#(loaded_private_key, _)) = keys.key_pair_from_base64(seed)
  assert eddsa.to_bytes(loaded_private_key) == eddsa.to_bytes(private_key)
}

pub fn key_pair_from_base64_invalid_base64_test() {
  assert keys.key_pair_from_base64("not-valid-base64!!!")
    == Error(keys.InvalidBase64)
}

pub fn key_pair_from_base64_invalid_length_test() {
  let too_short = bit_array.base64_encode(<<1, 2, 3>>, True)
  assert keys.key_pair_from_base64(too_short) == Error(keys.InvalidKeyBytes)
}

pub fn public_key_from_base64_round_trip_test() {
  let #(_private_key, public_key) = keys.generate()
  let encoded =
    bit_array.base64_encode(eddsa.public_key_to_bytes(public_key), True)

  let assert Ok(loaded_public_key) = keys.public_key_from_base64(encoded)
  assert eddsa.public_key_to_bytes(loaded_public_key)
    == eddsa.public_key_to_bytes(public_key)
}

pub fn private_key_to_pem_round_trip_test() {
  let #(private_key, _public_key) = keys.generate()
  let assert Ok(pem) = keys.private_key_to_pem(private_key)
  let assert Ok(#(loaded_private_key, _)) = keys.key_pair_from_pem(pem)
  assert eddsa.to_bytes(loaded_private_key) == eddsa.to_bytes(private_key)
}

pub fn public_key_to_pem_round_trip_test() {
  let #(_private_key, public_key) = keys.generate()
  let assert Ok(pem) = keys.public_key_to_pem(public_key)
  let assert Ok(loaded_public_key) = keys.public_key_from_pem(pem)
  assert eddsa.public_key_to_bytes(loaded_public_key)
    == eddsa.public_key_to_bytes(public_key)
}
