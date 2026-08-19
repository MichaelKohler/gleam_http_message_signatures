import gleam/option.{None, Some}
import http_message_signatures/component.{Derived, Field, Method, QueryParam}
import http_message_signatures/params.{SignatureParams}
import structured_fields/types.{BareString, InnerList, Integer, Item, Parameter}

pub fn round_trip_test() {
  let original =
    SignatureParams(
      components: [Field("date"), Derived(Method), Derived(QueryParam("baz"))],
      key_id: "test-key",
      algorithm: "ed25519",
      created: Some(1_618_884_473),
      expires: Some(1_618_884_573),
    )

  let element = params.to_element(original)
  assert params.from_element(element) == Ok(original)
}

pub fn round_trip_without_optional_params_test() {
  let original =
    SignatureParams(
      components: [Field("date")],
      key_id: "test-key",
      algorithm: "ed25519",
      created: None,
      expires: None,
    )

  let element = params.to_element(original)
  assert params.from_element(element) == Ok(original)
}

pub fn to_element_parameter_order_test() {
  let signature_params =
    SignatureParams(
      components: [Derived(Method)],
      key_id: "test-key",
      algorithm: "ed25519",
      created: Some(1_618_884_473),
      expires: Some(1_618_884_573),
    )

  assert params.to_element(signature_params)
    == InnerList([Item(BareString("@method"), [])], [
      Parameter("keyid", BareString("test-key")),
      Parameter("alg", BareString("ed25519")),
      Parameter("created", Integer(1_618_884_473)),
      Parameter("expires", Integer(1_618_884_573)),
    ])
}

pub fn from_element_requires_inner_list_test() {
  assert params.from_element(Item(BareString("@method"), []))
    == Error(params.NotAnInnerList)
}

pub fn from_element_requires_keyid_test() {
  let element =
    InnerList([Item(BareString("@method"), [])], [
      Parameter("alg", BareString("ed25519")),
    ])
  assert params.from_element(element) == Error(params.MissingKeyId)
}

pub fn from_element_requires_alg_test() {
  let element =
    InnerList([Item(BareString("@method"), [])], [
      Parameter("keyid", BareString("test-key")),
    ])
  assert params.from_element(element) == Error(params.MissingAlgorithm)
}

pub fn from_element_rejects_unknown_derived_component_test() {
  let element =
    InnerList([Item(BareString("@bogus"), [])], [
      Parameter("keyid", BareString("test-key")),
      Parameter("alg", BareString("ed25519")),
    ])
  assert params.from_element(element)
    == Error(params.InvalidComponentIdentifier)
}
