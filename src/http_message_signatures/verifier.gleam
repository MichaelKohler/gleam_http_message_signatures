//// Public verification API.
////
//// Two-step by design: a real verifier needs to inspect `keyid` (via
//// `parse`) before it can even look up which public key to verify against,
//// so a single monolithic `verify` can't model that.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, Some}
import gleam/result
import kryptos/eddsa
import structured_fields/parser
import structured_fields/types.{ByteSequence, Item}

import http_message_signatures/component
import http_message_signatures/keys
import http_message_signatures/message.{type Message}
import http_message_signatures/params.{type SignatureParams}

pub type VerifyError {
  SignatureLabelNotFound
  SignatureInputParseError
  SignatureParseError
  MalformedSignatureParams
  UnsupportedAlgorithm(String)
  ComponentError(component.ComponentError)
  MissingRequiredComponent(component.ComponentIdentifier)
  SignatureExpired
  SignatureTooOld
  InvalidSignature
}

/// Parses the `Signature-Input` header and extracts the parameters for
/// `label`, so the caller can inspect `keyid` before picking a key to verify
/// with.
pub fn parse(
  signature_input_header: String,
  label: String,
) -> Result(SignatureParams, VerifyError) {
  use entries <- result.try(
    parser.parse_dictionary(signature_input_header)
    |> result.replace_error(SignatureInputParseError),
  )

  use element <- result.try(
    list.key_find(entries, label)
    |> result.replace_error(SignatureLabelNotFound),
  )

  params.from_element(element)
  |> result.replace_error(MalformedSignatureParams)
}

/// Verifies `message` against `signature_header` under `label`, using
/// `public_key` and the previously-parsed `signature_params`.
///
/// Checks run cheapest-first: `required_components` coverage (RFC 9421 §7.2
/// — an insufficient or attacker-chosen covered set is a real attack
/// surface, so callers must state what has to be covered), algorithm
/// (`UnsupportedAlgorithm` for anything other than `"ed25519"` — the same
/// algorithm-confusion guard as `signer.sign`), expiry, max age, and finally
/// the signature bytes themselves.
pub fn verify(
  message: Message,
  public_key: keys.PublicKey,
  signature_params: SignatureParams,
  signature_header: String,
  label: String,
  required_components: List(component.ComponentIdentifier),
  now: Int,
  max_age_seconds: Option(Int),
) -> Result(Nil, VerifyError) {
  use _ <- result.try(check_required_components(
    signature_params.components,
    required_components,
  ))
  use _ <- result.try(check_algorithm(signature_params.algorithm))
  use _ <- result.try(check_expiry(signature_params, now))
  use _ <- result.try(check_max_age(signature_params, now, max_age_seconds))

  let params_element = params.to_element(signature_params)

  use base <- result.try(
    component.signature_base(
      signature_params.components,
      message,
      params_element,
    )
    |> result.map_error(ComponentError),
  )

  use signature_bytes <- result.try(extract_signature(signature_header, label))

  case eddsa.verify(public_key, bit_array.from_string(base), signature_bytes) {
    True -> Ok(Nil)
    False -> Error(InvalidSignature)
  }
}

fn check_required_components(
  covered: List(component.ComponentIdentifier),
  required: List(component.ComponentIdentifier),
) -> Result(Nil, VerifyError) {
  case list.find(required, fn(id) { !list.contains(covered, id) }) {
    Ok(missing) -> Error(MissingRequiredComponent(missing))
    Error(_) -> Ok(Nil)
  }
}

fn check_algorithm(algorithm: String) -> Result(Nil, VerifyError) {
  case algorithm {
    "ed25519" -> Ok(Nil)
    other -> Error(UnsupportedAlgorithm(other))
  }
}

fn check_expiry(
  signature_params: SignatureParams,
  now: Int,
) -> Result(Nil, VerifyError) {
  case signature_params.expires {
    Some(expires) if now > expires -> Error(SignatureExpired)
    _ -> Ok(Nil)
  }
}

fn check_max_age(
  signature_params: SignatureParams,
  now: Int,
  max_age_seconds: Option(Int),
) -> Result(Nil, VerifyError) {
  case max_age_seconds, signature_params.created {
    Some(max_age), Some(created) if now - created > max_age ->
      Error(SignatureTooOld)
    _, _ -> Ok(Nil)
  }
}

fn extract_signature(
  signature_header: String,
  label: String,
) -> Result(BitArray, VerifyError) {
  use entries <- result.try(
    parser.parse_dictionary(signature_header)
    |> result.replace_error(SignatureParseError),
  )

  use element <- result.try(
    list.key_find(entries, label)
    |> result.replace_error(SignatureLabelNotFound),
  )

  case element {
    Item(ByteSequence(bytes), []) -> Ok(bytes)
    _ -> Error(SignatureParseError)
  }
}
