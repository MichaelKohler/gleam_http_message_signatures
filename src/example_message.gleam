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
          request,
          public_key,
          signature_params,
          signed.signature,
          "sig1",
          [Derived(Method), Derived(Authority)],
          1_618_884_473,
          None,
        )
      {
        Ok(Nil) -> io.println("Verification succeeded!")
        Error(error) ->
          io.println("Verification failed: " <> string.inspect(error))
      }
    }
    Error(error) -> io.println("Signing failed: " <> string.inspect(error))
  }
}
