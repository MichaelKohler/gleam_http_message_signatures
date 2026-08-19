//// Public signing API.

import gleam/bit_array
import gleam/result
import kryptos/eddsa
import structured_fields/serializer
import structured_fields/types.{ByteSequence, Item}

import http_message_signatures/component
import http_message_signatures/keys
import http_message_signatures/message.{type Message}
import http_message_signatures/params.{type SignatureParams}

pub type SignError {
  UnsupportedAlgorithm(String)
  ComponentError(component.ComponentError)
}

pub type SignedHeaders {
  SignedHeaders(signature_input: String, signature: String)
}

/// Signs `message`, covering `signature_params.components`, and returns the
/// `Signature-Input`/`Signature` header values to attach to the outgoing
/// message. This library only computes header values — it does not touch a
/// transport-layer request object.
///
/// Only the `"ed25519"` algorithm is implemented: any other
/// `signature_params.algorithm` value short-circuits with
/// `UnsupportedAlgorithm` before any component canonicalization or crypto
/// happens.
pub fn sign(
  message: Message,
  private_key: keys.PrivateKey,
  label: String,
  signature_params: SignatureParams,
) -> Result(SignedHeaders, SignError) {
  case signature_params.algorithm {
    "ed25519" -> sign_ed25519(message, private_key, label, signature_params)
    other -> Error(UnsupportedAlgorithm(other))
  }
}

fn sign_ed25519(
  message: Message,
  private_key: keys.PrivateKey,
  label: String,
  signature_params: SignatureParams,
) -> Result(SignedHeaders, SignError) {
  let params_element = params.to_element(signature_params)

  use base <- result.try(
    component.signature_base(
      signature_params.components,
      message,
      params_element,
    )
    |> result.map_error(ComponentError),
  )

  let signature_bytes = eddsa.sign(private_key, bit_array.from_string(base))

  let signature_input =
    serializer.serialize_dictionary([#(label, params_element)])
  let signature =
    serializer.serialize_dictionary([
      #(label, Item(ByteSequence(signature_bytes), [])),
    ])

  Ok(SignedHeaders(signature_input, signature))
}
