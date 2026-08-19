import gleam/io
import gleam/string
import http_signatures/signatures

pub fn main() {
  let value = "{hello:\"world\"}"
  let signature = signatures.create_signature(...)

  case signature {
    Ok(v) -> io.println("Value: " <> v)
    Error(e) ->
      io.println("Error creating signature: " <> string.inspect(e))
  }
}
