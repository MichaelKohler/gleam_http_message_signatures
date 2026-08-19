import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import http_message_signatures/component.{
  Authority, Derived, Field, Method, Path,
}
import http_message_signatures/keys
import http_message_signatures/message.{Request}
import http_message_signatures/params.{SignatureParams}
import http_message_signatures/signer
import http_message_signatures/verifier
import kryptos/eddsa
import structured_fields/parser
import structured_fields/serializer
import structured_fields/types.{
  type Element, BareString, ByteSequence, InnerList, Integer, Item, Parameter,
}

// RFC 9421 Appendix B.1.4 "Example Ed25519 Test Key" (test-key-ed25519),
// copied verbatim from https://www.rfc-editor.org/rfc/rfc9421.html.
const test_key_public_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----"

const test_key_private_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----"

const created = 1_618_884_473

const b26_covered_components = [
  Field("date"),
  Derived(Method),
  Derived(Path),
  Derived(Authority),
  Field("content-type"),
  Field("content-length"),
]

// Appendix B.2's shared "test-request" message, covering the fields used by
// the B.2.6 example (date, @method, @path, @authority, content-type,
// content-length) plus the untouched content-digest field for authenticity.
fn test_request() -> message.Message {
  Request("POST", "https://example.com/foo?param=Value&Pet=dog", [
    #("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
    #("Content-Type", "application/json"),
    #(
      "Content-Digest",
      "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    ),
    #("Content-Length", "18"),
  ])
}

// The exact `@signature-params` element as printed in RFC 9421 §B.2.6 — note
// it has no `alg` parameter, since the RFC's non-normative example assumes
// the verifier already knows the algorithm from the identified key. Built by
// hand (rather than via `params.to_element`) so the "fidelity to the RFC
// text" tests below don't depend on this library's own policy of always
// serializing `alg` explicitly.
fn b26_rfc_literal_element() -> Element {
  InnerList(
    [
      Item(BareString("date"), []),
      Item(BareString("@method"), []),
      Item(BareString("@path"), []),
      Item(BareString("@authority"), []),
      Item(BareString("content-type"), []),
      Item(BareString("content-length"), []),
    ],
    [
      Parameter("created", Integer(created)),
      Parameter("keyid", BareString("test-key-ed25519")),
    ],
  )
}

// This library's own `SignatureParams` for the same covered components —
// `alg` is always present and explicit here (RFC §7.2's algorithm-confusion
// mitigation), which is why signing with it produces different bytes than
// the RFC's literal example; see `sign_bytes_differ_from_rfc_literal_test`.
fn b26_signature_params() -> params.SignatureParams {
  SignatureParams(
    components: b26_covered_components,
    key_id: "test-key-ed25519",
    algorithm: "ed25519",
    created: Some(created),
    expires: None,
  )
}

pub fn signature_base_matches_rfc_b26_text_test() {
  let expected =
    "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
    <> "\"@method\": POST\n"
    <> "\"@path\": /foo\n"
    <> "\"@authority\": example.com\n"
    <> "\"content-type\": application/json\n"
    <> "\"content-length\": 18\n"
    <> "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""

  assert component.signature_base(
      b26_covered_components,
      test_request(),
      b26_rfc_literal_element(),
    )
    == Ok(expected)
}

pub fn sign_bytes_match_rfc_b26_vector_test() {
  // Validates keys.gleam's PEM loading and component.gleam's canonicalization
  // against the RFC's own worked example, byte-for-byte: sign the exact RFC
  // signature base with the exact RFC key and compare against the RFC's
  // literal Signature value (Appendix B.2.6), copied verbatim from the RFC.
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(base) =
    component.signature_base(
      b26_covered_components,
      test_request(),
      b26_rfc_literal_element(),
    )

  let signature_bytes = eddsa.sign(private_key, bit_array.from_string(base))

  let assert Ok(expected_signature_bytes) =
    bit_array.base64_decode(
      "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
    )

  assert signature_bytes == expected_signature_bytes
  assert eddsa.verify(public_key, bit_array.from_string(base), signature_bytes)
}

pub fn verify_rfc_b26_vector_signature_bytes_test() {
  let assert Ok(public_key) = keys.public_key_from_pem(test_key_public_pem)

  let assert Ok(base) =
    component.signature_base(
      b26_covered_components,
      test_request(),
      b26_rfc_literal_element(),
    )

  let assert Ok(signature_bytes) =
    bit_array.base64_decode(
      "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
    )

  assert eddsa.verify(public_key, bit_array.from_string(base), signature_bytes)
}

pub fn sign_produces_correctly_ordered_signature_input_test() {
  let assert Ok(#(private_key, _public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  // Same covered components and `created` as the RFC text, but with this
  // library's always-explicit `alg` parameter added after `keyid`.
  assert signed.signature_input
    == "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");keyid=\"test-key-ed25519\";alg=\"ed25519\";created=1618884473"
}

pub fn sign_then_verify_b26_round_trip_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  assert verifier.verify(
      test_request(),
      public_key,
      b26_signature_params(),
      signed.signature,
      "sig-b26",
      [Derived(Method), Derived(Authority)],
      created,
      None,
    )
    == Ok(Nil)
}

pub fn sign_then_verify_round_trip_test() {
  let #(private_key, public_key) = keys.generate()

  let signature_params =
    SignatureParams(
      components: [Derived(Method), Derived(Authority), Field("date")],
      key_id: "my-key",
      algorithm: "ed25519",
      created: Some(1000),
      expires: None,
    )

  let request =
    Request("GET", "https://example.com/foo", [#("Date", "some-date")])

  let assert Ok(signed) =
    signer.sign(request, private_key, "sig1", signature_params)

  assert verifier.verify(
      request,
      public_key,
      signature_params,
      signed.signature,
      "sig1",
      [Derived(Method)],
      1000,
      None,
    )
    == Ok(Nil)
}

pub fn tampered_signature_bytes_fail_verification_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  let tampered_signature =
    flip_first_signature_byte(signed.signature, "sig-b26")

  assert verifier.verify(
      test_request(),
      public_key,
      b26_signature_params(),
      tampered_signature,
      "sig-b26",
      [],
      created,
      None,
    )
    == Error(verifier.InvalidSignature)
}

fn flip_first_signature_byte(
  signature_header: String,
  label: String,
) -> String {
  let assert Ok(entries) = parser.parse_dictionary(signature_header)
  let assert Ok(Item(ByteSequence(bytes), [])) = list.key_find(entries, label)
  let flipped_bytes = flip_first_byte(bytes)
  serializer.serialize_dictionary([
    #(label, Item(ByteSequence(flipped_bytes), [])),
  ])
}

fn flip_first_byte(bytes: BitArray) -> BitArray {
  case bytes {
    <<byte, rest:bytes>> ->
      bit_array.append(<<int.bitwise_exclusive_or(byte, 1)>>, rest)
    other -> other
  }
}

pub fn tampering_a_covered_header_fails_verification_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  let mutated_request =
    Request("POST", "https://example.com/foo?param=Value&Pet=dog", [
      #("Date", "Tue, 20 Apr 2021 02:07:56 GMT"),
      #("Content-Type", "application/json"),
      #("Content-Length", "18"),
    ])

  assert verifier.verify(
      mutated_request,
      public_key,
      b26_signature_params(),
      signed.signature,
      "sig-b26",
      [],
      created,
      None,
    )
    == Error(verifier.InvalidSignature)
}

pub fn tampering_an_uncovered_header_still_verifies_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  let request_with_extra_header =
    Request("POST", "https://example.com/foo?param=Value&Pet=dog", [
      #("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
      #("Content-Type", "application/json"),
      #("Content-Length", "18"),
      #("X-Not-Covered", "anything goes here"),
    ])

  assert verifier.verify(
      request_with_extra_header,
      public_key,
      b26_signature_params(),
      signed.signature,
      "sig-b26",
      [],
      created,
      None,
    )
    == Ok(Nil)
}

pub fn missing_required_component_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  let result =
    verifier.verify(
      test_request(),
      public_key,
      b26_signature_params(),
      signed.signature,
      "sig-b26",
      [Field("content-digest")],
      created,
      None,
    )

  assert result
    == Error(verifier.MissingRequiredComponent(Field("content-digest")))
}

pub fn signature_expired_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let signature_params =
    SignatureParams(..b26_signature_params(), expires: Some(created + 10))

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", signature_params)

  assert verifier.verify(
      test_request(),
      public_key,
      signature_params,
      signed.signature,
      "sig-b26",
      [],
      created + 20,
      None,
    )
    == Error(verifier.SignatureExpired)
}

pub fn signature_too_old_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  assert verifier.verify(
      test_request(),
      public_key,
      b26_signature_params(),
      signed.signature,
      "sig-b26",
      [],
      created + 100,
      Some(60),
    )
    == Error(verifier.SignatureTooOld)
}

pub fn signer_rejects_unsupported_algorithm_test() {
  let #(private_key, _public_key) = keys.generate()

  let signature_params =
    SignatureParams(..b26_signature_params(), algorithm: "rsa-pss-sha512")

  assert signer.sign(test_request(), private_key, "sig1", signature_params)
    == Error(signer.UnsupportedAlgorithm("rsa-pss-sha512"))
}

pub fn verifier_rejects_unsupported_algorithm_test() {
  let assert Ok(#(private_key, public_key)) =
    keys.key_pair_from_pem(test_key_private_pem)

  let assert Ok(signed) =
    signer.sign(test_request(), private_key, "sig-b26", b26_signature_params())

  let signature_params =
    SignatureParams(..b26_signature_params(), algorithm: "rsa-pss-sha512")

  assert verifier.verify(
      test_request(),
      public_key,
      signature_params,
      signed.signature,
      "sig-b26",
      [],
      created,
      None,
    )
    == Error(verifier.UnsupportedAlgorithm("rsa-pss-sha512"))
}

pub fn verifier_parse_extracts_params_from_signature_input_test() {
  let assert Ok(parsed) =
    verifier.parse(
      "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");keyid=\"test-key-ed25519\";alg=\"ed25519\";created=1618884473",
      "sig-b26",
    )

  assert parsed == b26_signature_params()
}

pub fn verifier_parse_rejects_missing_label_test() {
  let result =
    verifier.parse(
      "sig1=(\"@method\");keyid=\"test-key\";alg=\"ed25519\";created=1618884473",
      "sig-b26",
    )
  assert result == Error(verifier.SignatureLabelNotFound)
}

pub fn verifier_parse_rejects_rfc_style_input_missing_alg_test() {
  // Demonstrates a deliberate divergence from the RFC's own non-normative
  // examples: this library requires `alg` to always be present (RFC §7.2's
  // algorithm-confusion mitigation), so a Signature-Input value shaped like
  // the RFC's literal B.2.6 example (which omits `alg`) is rejected rather
  // than accepted on a best-effort basis.
  let result =
    verifier.parse(
      "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
      "sig-b26",
    )
  assert result == Error(verifier.MalformedSignatureParams)
}
