# http_message_signatures

[![Package Version](https://img.shields.io/hexpm/v/http_message_signatures)](https://hex.pm/packages/http_message_signatures)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://http-message-signatures.hexdocs.pm/)

A minimal, framework-agnostic implementation of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) (HTTP Message Signatures), targeting both the Erlang and JavaScript backends. It does not yet cover 100% of the RFC, see below for unsupported areas.

```sh
gleam add http_message_signatures
```

```gleam
import gleam/option.{None, Some}
import http_message_signatures/component.{Authority, Derived, Field, Method}
import http_message_signatures/keys
import http_message_signatures/message.{Request}
import http_message_signatures/params.{SignatureParams}
import http_message_signatures/signer
import http_message_signatures/verifier

pub fn main() {
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

  let assert Ok(signed) =
    signer.sign(request, private_key, "sig1", signature_params)

  // Attach `signed.signature_input` and `signed.signature` as the
  // `Signature-Input` and `Signature` headers on the outgoing request.

  let assert Ok(Nil) =
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
}
```

This library only computes and checks header *values* — it has no dependency
on any HTTP framework, so it works with `mist`, `wisp`, `httpc`, or anything
else.

## Not yet supported

PRs are welcome for any of the following:

- Any signature algorithm other than Ed25519. `SignatureParams.algorithm` is
  a free-form string (not a closed enum), so it's already possible to
  construct params for other RFC 9421 §6.3-registered algorithms — `sign`
  and `verify` will just return `UnsupportedAlgorithm` for anything other
  than `"ed25519"`.
- Multiple signatures per message — only a single `Signature-Input`/`Signature`
  label is produced per call to `sign`.
- Structured-field component parameters: `sf`, `key`, `bs` (RFC §2.1.1–2.1.3).
- Trailer fields / the `tr` parameter (RFC §2.1.4).
- Request-response binding / the `req` parameter (RFC §2.4).
- Signature negotiation (`Accept-Signature`, RFC §5).
- `nonce` and `tag` signature parameters (RFC §2.3) — accepted as
  "recognized but unused."
- Non-origin-form `@request-target` (absolute-form, authority-form,
  asterisk-form — RFC §2.2.5). Only `method + path + query` requests are
  supported.

## Development

```sh
gleam run -m example_message
gleam test
gleam test --target javascript
```
