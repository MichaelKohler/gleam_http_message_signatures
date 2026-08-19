import gleam/io
import gleam/option.{None, Some}
import gleam/string
import http_message_signatures/component.{Authority, Derived, Field, Method}
import http_message_signatures/keys
import http_message_signatures/message.{Request}
import http_message_signatures/params.{SignatureParams}
import http_message_signatures/signer
import http_message_signatures/verifier

pub fn main() -> Nil {
  let #(private_key, public_key) = keys.generate()

  let request =
    Request("POST", "https://example.com/foo", [
      #("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
      #("Content-Type", "application/json"),
    ])

  let signature_params =
    SignatureParams(
      components: [Derived(Method), Derived(Authority), Field("date")],
      key_id: "example-key",
      algorithm: "ed25519",
      created: Some(1_618_884_473),
      expires: None,
    )

  case signer.sign(request, private_key, "sig1", signature_params) {
    Ok(signed) -> {
      io.println("Signature-Input: " <> signed.signature_input)
      io.println("Signature: " <> signed.signature)

      case
        verifier.verify(
          message: request,
          public_key: public_key,
          signature_params: signature_params,
          signature_header: signed.signature,
          label: "sig1",
          policy: verifier.VerifyPolicy(
            required_components: [Derived(Method), Derived(Authority)],
            now: 1_618_884_473,
            max_age_seconds: None,
          ),
        )
      {
        Ok(Nil) -> io.println("Verification succeeded!")
        Error(error) ->
          io.println("Verification failed: " <> string.inspect(error))
      }
    }
    Error(error) -> io.println("Signing failed: " <> string.inspect(error))
  }

  demo_multiple_signatures(request)
}

/// Demonstrates signing the same message twice under different labels (e.g.
/// once by the client, once by a forwarding proxy) and combining both into
/// one Signature-Input/Signature header pair.
fn demo_multiple_signatures(request: message.Message) -> Nil {
  let #(client_key, _client_public_key) = keys.generate()
  let #(proxy_key, _proxy_public_key) = keys.generate()

  let client_params =
    SignatureParams(
      components: [Derived(Method), Field("date")],
      key_id: "client-key",
      algorithm: "ed25519",
      created: Some(1_618_884_473),
      expires: None,
    )

  let proxy_params =
    SignatureParams(
      components: [Derived(Authority)],
      key_id: "proxy-key",
      algorithm: "ed25519",
      created: Some(1_618_884_473),
      expires: None,
    )

  let assert Ok(client_signed) =
    signer.sign_one(request, client_key, "client", client_params)
  let assert Ok(proxy_signed) =
    signer.sign_one(request, proxy_key, "proxy", proxy_params)

  case signer.combine([client_signed, proxy_signed]) {
    Ok(signed) -> {
      io.println("\nMultiple signatures on one message:")
      io.println("Signature-Input: " <> signed.signature_input)
      io.println("Signature: " <> signed.signature)
    }
    Error(error) ->
      io.println("Combining signatures failed: " <> string.inspect(error))
  }
}
