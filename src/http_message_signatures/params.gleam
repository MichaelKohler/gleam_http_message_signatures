//// Signature parameters (RFC 9421 §2.3, §4.1): the covered components plus
//// `keyid`, `alg`, `created`, and `expires`.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import structured_fields/types.{
  type BareItem, type Element, type Parameter, BareString, InnerList, Integer,
  Item, Parameter,
}

import http_message_signatures/component.{
  type ComponentIdentifier, type DerivedComponent, Authority, Derived, Field,
  Method, Path, Query, QueryParam, RequestTarget, Scheme, Status, TargetUri,
}

pub type SignatureParams {
  SignatureParams(
    components: List(ComponentIdentifier),
    key_id: String,
    algorithm: String,
    created: Option(Int),
    expires: Option(Int),
  )
}

pub type FromElementError {
  NotAnInnerList
  InvalidComponentIdentifier
  MissingKeyId
  MissingAlgorithm
}

/// Serializes signature parameters to the `InnerList` Structured Fields
/// `Element` used both as the `@signature-params` signature-base line value
/// and as the value stored under the label in `Signature-Input`.
pub fn to_element(params: SignatureParams) -> Element {
  let component_elements =
    list.map(params.components, component.identifier_to_element)

  let top_level_parameters =
    [
      Parameter("keyid", BareString(params.key_id)),
      Parameter("alg", BareString(params.algorithm)),
    ]
    |> append_if_some("created", params.created)
    |> append_if_some("expires", params.expires)

  InnerList(component_elements, top_level_parameters)
}

fn append_if_some(
  parameters: List(Parameter),
  name: String,
  value: Option(Int),
) -> List(Parameter) {
  case value {
    None -> parameters
    Some(v) -> list.append(parameters, [Parameter(name, Integer(v))])
  }
}

/// Parses signature parameters back from their `InnerList` element. Fails
/// closed: any unrecognized structure (unknown derived component name, a
/// component identifier carrying unsupported parameters, a missing `keyid`
/// or `alg`, ...) is a parse error rather than a best-effort partial parse.
pub fn from_element(
  element: Element,
) -> Result(SignatureParams, FromElementError) {
  case element {
    InnerList(items, top_level_parameters) -> {
      use components <- result.try(list.try_map(items, item_to_identifier))
      use key_id <- result.try(
        find_string_parameter(top_level_parameters, "keyid")
        |> result.replace_error(MissingKeyId),
      )
      use algorithm <- result.try(
        find_string_parameter(top_level_parameters, "alg")
        |> result.replace_error(MissingAlgorithm),
      )
      let created = find_int_parameter(top_level_parameters, "created")
      let expires = find_int_parameter(top_level_parameters, "expires")

      Ok(SignatureParams(components, key_id, algorithm, created, expires))
    }
    _ -> Error(NotAnInnerList)
  }
}

fn item_to_identifier(
  item: Element,
) -> Result(ComponentIdentifier, FromElementError) {
  case item {
    Item(BareString("@query-param"), item_parameters) ->
      case find_string_parameter(item_parameters, "name") {
        Ok(name) -> Ok(Derived(QueryParam(name)))
        Error(_) -> Error(InvalidComponentIdentifier)
      }

    Item(BareString(name), []) ->
      case derived_component_from_name(name) {
        Some(derived) -> Ok(Derived(derived))
        None ->
          case string.starts_with(name, "@") {
            True -> Error(InvalidComponentIdentifier)
            False -> Ok(Field(name))
          }
      }

    _ -> Error(InvalidComponentIdentifier)
  }
}

fn derived_component_from_name(name: String) -> Option(DerivedComponent) {
  case name {
    "@method" -> Some(Method)
    "@target-uri" -> Some(TargetUri)
    "@authority" -> Some(Authority)
    "@scheme" -> Some(Scheme)
    "@request-target" -> Some(RequestTarget)
    "@path" -> Some(Path)
    "@query" -> Some(Query)
    "@status" -> Some(Status)
    _ -> None
  }
}

fn find_parameter(
  parameters: List(Parameter),
  name: String,
) -> Result(BareItem, Nil) {
  parameters
  |> list.find(fn(parameter) { parameter.name == name })
  |> result.map(fn(parameter) { parameter.value })
}

fn find_string_parameter(
  parameters: List(Parameter),
  name: String,
) -> Result(String, Nil) {
  case find_parameter(parameters, name) {
    Ok(BareString(value)) -> Ok(value)
    _ -> Error(Nil)
  }
}

fn find_int_parameter(
  parameters: List(Parameter),
  name: String,
) -> Option(Int) {
  case find_parameter(parameters, name) {
    Ok(Integer(value)) -> Some(value)
    _ -> None
  }
}
