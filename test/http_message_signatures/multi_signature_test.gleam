import gleam/option.{None, Some}
import gleam/string
import http_message_signatures/component.{Authority, Derived, Field, Method}
import http_message_signatures/keys
import http_message_signatures/message.{Request}
import http_message_signatures/params.{SignatureParams}
import http_message_signatures/signer
import http_message_signatures/verifier

fn client_params() -> params.SignatureParams {
  SignatureParams(
    components: [Derived(Method), Field("date")],
    key_id: "client-key",
    algorithm: "ed25519",
    created: Some(1000),
    expires: None,
  )
}

fn proxy_params() -> params.SignatureParams {
  SignatureParams(
    components: [Derived(Authority)],
    key_id: "proxy-key",
    algorithm: "ed25519",
    created: Some(1000),
    expires: None,
  )
}

fn request() -> message.Message {
  Request("POST", "https://example.com/foo", [
    #("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
  ])
}

pub fn combine_packs_multiple_labels_into_one_dictionary_test() {
  let #(client_key, client_public_key) = keys.generate()
  let #(proxy_key, proxy_public_key) = keys.generate()

  let assert Ok(client_signed) =
    signer.sign_one(request(), client_key, "client", client_params())
  let assert Ok(proxy_signed) =
    signer.sign_one(request(), proxy_key, "proxy", proxy_params())

  let assert Ok(signed) = signer.combine([client_signed, proxy_signed])

  // Both labels show up in a single Signature-Input/Signature value.
  assert string.contains(signed.signature_input, "client=")
  assert string.contains(signed.signature_input, "proxy=")
  assert string.contains(signed.signature, "client=")
  assert string.contains(signed.signature, "proxy=")

  // Each signature verifies independently against the shared header value.
  assert verifier.verify(
      message: request(),
      public_key: client_public_key,
      signature_params: client_params(),
      signature_header: signed.signature,
      label: "client",
      policy: verifier.VerifyPolicy(
        required_components: [Derived(Method)],
        now: 1000,
        max_age_seconds: None,
      ),
    )
    == Ok(Nil)

  assert verifier.verify(
      message: request(),
      public_key: proxy_public_key,
      signature_params: proxy_params(),
      signature_header: signed.signature,
      label: "proxy",
      policy: verifier.VerifyPolicy(
        required_components: [Derived(Authority)],
        now: 1000,
        max_age_seconds: None,
      ),
    )
    == Ok(Nil)
}

pub fn combine_rejects_empty_list_test() {
  assert signer.combine([]) == Error(signer.EmptySignatureList)
}

pub fn combine_rejects_duplicate_labels_test() {
  let #(client_key, _client_public_key) = keys.generate()

  let assert Ok(first) =
    signer.sign_one(request(), client_key, "sig1", client_params())
  let assert Ok(second) =
    signer.sign_one(request(), client_key, "sig1", proxy_params())

  assert signer.combine([first, second]) == Error(signer.DuplicateLabel("sig1"))
}

pub fn sign_is_equivalent_to_sign_one_then_combine_test() {
  let #(private_key, _public_key) = keys.generate()

  let assert Ok(via_sign) =
    signer.sign(request(), private_key, "sig1", client_params())
  let assert Ok(one) =
    signer.sign_one(request(), private_key, "sig1", client_params())
  let assert Ok(via_combine) = signer.combine([one])

  assert via_sign == via_combine
}
