//// Public signing API.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import kryptos/eddsa
import structured_fields/serializer
import structured_fields/types.{type Element, ByteSequence, Item}

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

/// One signature produced by `sign_one`, not yet packed into header values.
/// `combine` composes one or more of these into a `SignedHeaders` — the unit
/// that supports signing the same message multiple times.
pub type Signed {
  Signed(label: String, params_element: Element, signature_bytes: BitArray)
}

pub type CombineError {
  EmptySignatureList
  DuplicateLabel(String)
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
///
/// To sign the same message multiple times (e.g. once by the client, once by
/// a forwarding proxy, each potentially with a different key or covered
/// component set), use `sign_one` and `combine` instead: RFC 9421 models
/// each signature independently, so composing several `Signed` values is
/// more flexible than a single call that takes a list of labels.
pub fn sign(
  message: Message,
  private_key: keys.PrivateKey,
  label: String,
  signature_params: SignatureParams,
) -> Result(SignedHeaders, SignError) {
  use signed <- result.try(sign_one(
    message,
    private_key,
    label,
    signature_params,
  ))
  Ok(to_signed_headers([signed]))
}

/// Produces a single signature without packing it into header values, so it
/// can be combined with others via `combine` to sign one message multiple
/// times under different labels. Prefer `sign` for the common single-
/// signature case.
pub fn sign_one(
  message: Message,
  private_key: keys.PrivateKey,
  label: String,
  signature_params: SignatureParams,
) -> Result(Signed, SignError) {
  case signature_params.algorithm {
    "ed25519" -> sign_one_ed25519(message, private_key, label, signature_params)
    other -> Error(UnsupportedAlgorithm(other))
  }
}

fn sign_one_ed25519(
  message: Message,
  private_key: keys.PrivateKey,
  label: String,
  signature_params: SignatureParams,
) -> Result(Signed, SignError) {
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

  Ok(Signed(label, params_element, signature_bytes))
}

/// Packs one or more independently-produced `Signed` values (see
/// `sign_one`) into a single `Signature-Input`/`Signature` header pair, per
/// RFC 9421's dictionary-of-labels model for multiple signatures on the same
/// message. Fails if `signed` is empty or if two entries share a label —
/// each signature on a message must have a distinct label.
pub fn combine(signed: List(Signed)) -> Result(SignedHeaders, CombineError) {
  case signed {
    [] -> Error(EmptySignatureList)
    _ ->
      case find_duplicate_label(signed, []) {
        Some(label) -> Error(DuplicateLabel(label))
        None -> Ok(to_signed_headers(signed))
      }
  }
}

fn find_duplicate_label(
  signed: List(Signed),
  seen: List(String),
) -> Option(String) {
  case signed {
    [] -> None
    [first, ..rest] ->
      case list.contains(seen, first.label) {
        True -> Some(first.label)
        False -> find_duplicate_label(rest, [first.label, ..seen])
      }
  }
}

fn to_signed_headers(signed: List(Signed)) -> SignedHeaders {
  let signature_input =
    serializer.serialize_dictionary(
      list.map(signed, fn(s) { #(s.label, s.params_element) }),
    )
  let signature =
    serializer.serialize_dictionary(
      list.map(signed, fn(s) {
        #(s.label, Item(ByteSequence(s.signature_bytes), []))
      }),
    )

  SignedHeaders(signature_input, signature)
}
