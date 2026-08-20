# http_message_signatures

[![Package Version](https://img.shields.io/hexpm/v/generic_http_message_signatures)](https://hex.pm/packages/generic_http_message_signatures)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://generic-http-message-signatures.hexdocs.pm/)

A minimal, framework-agnostic implementation of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) (HTTP Message Signatures), targeting both the Erlang and JavaScript backends. It does not yet cover 100% of the RFC, see below for unsupported areas.

```sh
gleam add generic_http_message_signatures
```

```gleam
import gleam/option.{None, Some}
import generic_http_message_signatures/component.{Authority, Derived, Field, Method}
import generic_http_message_signatures/keys
import generic_http_message_signatures/message.{Request}
import generic_http_message_signatures/params.{SignatureParams}
import generic_http_message_signatures/signer
import generic_http_message_signatures/verifier

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
}
```

This library only computes and checks header *values* — it has no dependency
on any HTTP framework, so it works with `mist`, `wisp`, `httpc`, or anything
else. `verify`'s `now` is always caller-supplied rather than read from the
system clock — this keeps verification deterministic and identical across
the Erlang and JavaScript targets, and trivially testable with fixed
timestamps.

### Multiple signatures on one message

RFC 9421 models `Signature-Input`/`Signature` as dictionaries, so several
independently-produced signatures (e.g. one from the client, one from a
forwarding proxy — each potentially with a different key, algorithm, or
covered-component set) can share one header pair under different labels.
Use `signer.sign_one` to produce each signature and `signer.combine` to pack
them together:

```gleam
let assert Ok(client_signed) =
  signer.sign_one(request, client_key, "client", client_params)
let assert Ok(proxy_signed) =
  signer.sign_one(request, proxy_key, "proxy", proxy_params)

let assert Ok(signed) = signer.combine([client_signed, proxy_signed])
```

`verifier.verify` already handles this on the way in — call it once per
label, passing the shared `signature_header`/`signature_input` value each
time; it extracts just the entry for the given `label` out of the
dictionary.

## Not yet supported

PRs are welcome for any of the following:

- Any signature algorithm other than Ed25519. `SignatureParams.algorithm` is
  a free-form string (not a closed enum), so it's already possible to
  construct params for other RFC 9421 §6.3-registered algorithms — `sign`
  and `verify` will just return `UnsupportedAlgorithm` for anything other
  than `"ed25519"`.
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
