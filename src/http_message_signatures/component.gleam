//// RFC 9421 §2 component identifiers, canonicalization, and signature base
//// assembly.
////
//// Covers: §2.1 (HTTP fields), §2.2.1-§2.2.9 (derived components, origin-form
//// `@request-target` only), and §2.5 (signature base creation). Structured-field
//// component parameters (`sf`, `key`, `bs`), trailer fields (`tr`), and
//// request-response binding (`req`) are out of scope — see the README.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri.{type Uri}
import structured_fields/serializer
import structured_fields/types.{type Element, BareString, Item, Parameter}

import http_message_signatures/message.{type Message, Request, Response}

pub type DerivedComponent {
  Method
  TargetUri
  Authority
  Scheme
  RequestTarget
  Path
  Query
  QueryParam(name: String)
  Status
}

pub type ComponentIdentifier {
  Derived(DerivedComponent)
  Field(name: String)
}

pub type ComponentError {
  HeaderNotFound(String)
  QueryParamNotFound(String)
  NotARequestComponent(DerivedComponent)
  NotAResponseComponent
  InvalidTargetUri(String)
}

/// Renders a component identifier as a Structured Fields `Element`, per RFC
/// 9421 §2.5 — the component name as a `BareString` Item, with any component
/// parameters (only `;name=` for `@query-param` is supported).
pub fn identifier_to_element(id: ComponentIdentifier) -> Element {
  case id {
    Derived(QueryParam(name)) ->
      Item(BareString("@query-param"), [Parameter("name", BareString(name))])
    Derived(component) ->
      Item(BareString(derived_component_name(component)), [])
    Field(name) -> Item(BareString(string.lowercase(name)), [])
  }
}

/// The strict Structured Fields serialization of a component identifier,
/// e.g. `"@method"` or `"@query-param";name="baz"`.
pub fn identifier_to_string(id: ComponentIdentifier) -> String {
  serializer.serialize_item(identifier_to_element(id))
}

fn derived_component_name(component: DerivedComponent) -> String {
  case component {
    Method -> "@method"
    TargetUri -> "@target-uri"
    Authority -> "@authority"
    Scheme -> "@scheme"
    RequestTarget -> "@request-target"
    Path -> "@path"
    Query -> "@query"
    QueryParam(_) -> "@query-param"
    Status -> "@status"
  }
}

/// Resolves a component identifier to its canonicalized string value for the
/// given message, per RFC 9421 §2.1 (HTTP fields) and §2.2 (derived
/// components).
pub fn component_value(
  id: ComponentIdentifier,
  message: Message,
) -> Result(String, ComponentError) {
  case id {
    Field(name) -> field_value(name, message)
    Derived(component) -> derived_value(component, message)
  }
}

fn message_headers(message: Message) -> List(#(String, String)) {
  case message {
    Request(_, _, headers) -> headers
    Response(_, headers) -> headers
  }
}

fn field_value(
  name: String,
  message: Message,
) -> Result(String, ComponentError) {
  let lower_name = string.lowercase(name)

  let matching_values =
    message
    |> message_headers
    |> list.filter(fn(header) { string.lowercase(header.0) == lower_name })
    |> list.map(fn(header) { string.trim(header.1) })

  case matching_values {
    [] -> Error(HeaderNotFound(name))
    values -> Ok(string.join(values, ", "))
  }
}

fn derived_value(
  component: DerivedComponent,
  message: Message,
) -> Result(String, ComponentError) {
  case component, message {
    Status, Response(status, _) -> Ok(int.to_string(status))
    Status, Request(..) -> Error(NotAResponseComponent)

    _, Response(..) -> Error(NotARequestComponent(component))

    Method, Request(method, _, _) -> Ok(method)
    TargetUri, Request(_, target_uri, _) -> Ok(target_uri)
    Authority, Request(_, target_uri, _) -> authority_value(target_uri)
    Scheme, Request(_, target_uri, _) ->
      result.map(parse_uri(target_uri), scheme_value)
    RequestTarget, Request(_, target_uri, _) ->
      result.map(parse_uri(target_uri), request_target_value)
    Path, Request(_, target_uri, _) ->
      result.map(parse_uri(target_uri), path_value)
    Query, Request(_, target_uri, _) ->
      result.map(parse_uri(target_uri), query_value)
    QueryParam(name), Request(_, target_uri, _) ->
      result.try(parse_uri(target_uri), fn(parsed) {
        query_param_value(parsed, name)
      })
  }
}

fn parse_uri(target_uri: String) -> Result(Uri, ComponentError) {
  uri.parse(target_uri)
  |> result.replace_error(InvalidTargetUri(target_uri))
}

fn authority_value(target_uri: String) -> Result(String, ComponentError) {
  use parsed <- result.try(parse_uri(target_uri))

  case parsed.host {
    None -> Error(InvalidTargetUri(target_uri))
    Some(host) -> {
      let lower_host = string.lowercase(host)

      case parsed.port {
        None -> Ok(lower_host)
        Some(port) -> {
          let is_default_port = case parsed.scheme {
            Some("http") -> port == 80
            Some("https") -> port == 443
            _ -> False
          }

          case is_default_port {
            True -> Ok(lower_host)
            False -> Ok(lower_host <> ":" <> int.to_string(port))
          }
        }
      }
    }
  }
}

fn scheme_value(parsed: Uri) -> String {
  parsed.scheme
  |> option.unwrap("")
  |> string.lowercase
}

fn path_value(parsed: Uri) -> String {
  case parsed.path {
    "" -> "/"
    path -> path
  }
}

fn query_value(parsed: Uri) -> String {
  "?" <> option.unwrap(parsed.query, "")
}

fn request_target_value(parsed: Uri) -> String {
  case parsed.query {
    None -> path_value(parsed)
    Some(query) -> path_value(parsed) <> "?" <> query
  }
}

fn query_param_value(
  parsed: Uri,
  name: String,
) -> Result(String, ComponentError) {
  case parsed.query {
    None -> Error(QueryParamNotFound(name))
    Some(query_string) -> lookup_query_param(query_string, name)
  }
}

/// Looks up `name` (already in canonical percent-encoded form) among the raw
/// query string's `&`-separated pairs, per RFC 9421 §2.2.8: each raw name and
/// value is decoded as `application/x-www-form-urlencoded` (`+` as space,
/// then percent-decoded) and re-encoded via "percent-encode after encoding"
/// (percent-encoding everything except `A-Z a-z 0-9 - . _ *`, notably *not*
/// re-encoding a decoded space back to `+`). A name occurring more than once
/// in the query string MUST NOT be included.
fn lookup_query_param(
  query_string: String,
  name: String,
) -> Result(String, ComponentError) {
  let canonical_pairs =
    query_string
    |> string.split("&")
    |> list.filter(fn(pair) { pair != "" })
    |> list.filter_map(fn(pair) {
      let #(raw_name, raw_value) = split_query_pair(pair)
      use decoded_name <- result.try(form_decode(raw_name))
      use decoded_value <- result.try(form_decode(raw_value))
      Ok(#(form_encode(decoded_name), form_encode(decoded_value)))
    })

  case list.filter(canonical_pairs, fn(pair) { pair.0 == name }) {
    [#(_, value)] -> Ok(value)
    _ -> Error(QueryParamNotFound(name))
  }
}

fn split_query_pair(pair: String) -> #(String, String) {
  case string.split_once(pair, "=") {
    Ok(#(name, value)) -> #(name, value)
    Error(_) -> #(pair, "")
  }
}

fn form_decode(input: String) -> Result(String, Nil) {
  input
  |> string.replace("+", " ")
  |> form_decode_loop(<<>>)
}

fn form_decode_loop(input: String, acc: BitArray) -> Result(String, Nil) {
  case string.pop_grapheme(input) {
    Error(_) -> bit_array.to_string(acc)
    Ok(#("%", rest)) -> {
      use #(hex1, rest) <- result.try(string.pop_grapheme(rest))
      use #(hex2, rest) <- result.try(string.pop_grapheme(rest))
      use byte <- result.try(hex_byte(hex1, hex2))
      form_decode_loop(rest, bit_array.append(acc, <<byte>>))
    }
    Ok(#(grapheme, rest)) ->
      form_decode_loop(
        rest,
        bit_array.append(acc, bit_array.from_string(grapheme)),
      )
  }
}

fn hex_byte(hex1: String, hex2: String) -> Result(Int, Nil) {
  use high <- result.try(hex_digit(hex1))
  use low <- result.try(hex_digit(hex2))
  Ok(high * 16 + low)
}

fn hex_digit(digit: String) -> Result(Int, Nil) {
  case string.lowercase(digit) {
    "0" -> Ok(0)
    "1" -> Ok(1)
    "2" -> Ok(2)
    "3" -> Ok(3)
    "4" -> Ok(4)
    "5" -> Ok(5)
    "6" -> Ok(6)
    "7" -> Ok(7)
    "8" -> Ok(8)
    "9" -> Ok(9)
    "a" -> Ok(10)
    "b" -> Ok(11)
    "c" -> Ok(12)
    "d" -> Ok(13)
    "e" -> Ok(14)
    "f" -> Ok(15)
    _ -> Error(Nil)
  }
}

fn form_encode(input: String) -> String {
  input
  |> bit_array.from_string
  |> form_encode_bytes
  |> string.concat
}

fn form_encode_bytes(bits: BitArray) -> List(String) {
  case bits {
    <<byte, rest:bytes>> -> [form_encode_byte(byte), ..form_encode_bytes(rest)]
    _ -> []
  }
}

fn form_encode_byte(byte: Int) -> String {
  case is_form_safe_byte(byte) {
    True -> {
      let assert Ok(char) = bit_array.to_string(<<byte>>)
      char
    }
    False -> "%" <> hex_upper(byte)
  }
}

fn is_form_safe_byte(byte: Int) -> Bool {
  { byte >= 0x30 && byte <= 0x39 }
  || { byte >= 0x41 && byte <= 0x5a }
  || { byte >= 0x61 && byte <= 0x7a }
  || byte == 0x2d
  || byte == 0x2e
  || byte == 0x5f
  || byte == 0x2a
}

fn hex_upper(byte: Int) -> String {
  hex_upper_digit(byte / 16) <> hex_upper_digit(byte % 16)
}

fn hex_upper_digit(digit: Int) -> String {
  case digit {
    0 -> "0"
    1 -> "1"
    2 -> "2"
    3 -> "3"
    4 -> "4"
    5 -> "5"
    6 -> "6"
    7 -> "7"
    8 -> "8"
    9 -> "9"
    10 -> "A"
    11 -> "B"
    12 -> "C"
    13 -> "D"
    14 -> "E"
    _ -> "F"
  }
}

/// Assembles the signature base (RFC 9421 §2.5): one line per covered
/// component, `identifier: value`, followed by the `@signature-params` line,
/// joined with `\n` (no trailing newline).
pub fn signature_base(
  components: List(ComponentIdentifier),
  message: Message,
  signature_params_element: Element,
) -> Result(String, ComponentError) {
  use lines <- result.try(
    list.try_map(components, fn(id) {
      use value <- result.try(component_value(id, message))
      Ok(identifier_to_string(id) <> ": " <> value)
    }),
  )

  let params_line =
    "\"@signature-params\": "
    <> serializer.serialize_item(signature_params_element)

  Ok(string.join(list.append(lines, [params_line]), "\n"))
}
