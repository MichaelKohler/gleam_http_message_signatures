# http_message_signatures

[![Package Version](https://img.shields.io/hexpm/v/http_message_signatures)](https://hex.pm/packages/http_message_signatures)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://http-message-signatures.hexdocs.pm/)

This library currently has support for creating message signature header values with the following algorithms:

* ...

PRs are welcome.

```sh
gleam add http_message_signatures
```

```gleam
import http_message_signatures/signatures

pub fn main() -> Nil {
  let value = "This is some content."
  ....
}
```

Further documentation can be found at <https://http-message-signatures.hexdocs.pm/>.

## Development

```sh
gleam run -m example_message
gleam test
```
