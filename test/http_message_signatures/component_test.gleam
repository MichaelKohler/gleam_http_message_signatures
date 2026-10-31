import gleam/list
import http_message_signatures/component.{
  Authority, Derived, Field, Method, NotARequestComponent, NotAResponseComponent,
  Path, Query, QueryParam, RequestTarget, Scheme, Status, TargetUri,
}
import http_message_signatures/message.{Request, Response}
import structured_fields/types.{BareString, InnerList, Integer, Item, Parameter}

fn example_request() -> message.Message {
  Request("POST", "https://www.example.com/path?param=value", [
    #("Host", "www.example.com"),
  ])
}

pub fn method_test() {
  assert component.component_value(Derived(Method), example_request())
    == Ok("POST")
}

pub fn target_uri_test() {
  let request = Request("POST", "https://www.example.com/path?param=value", [])
  assert component.component_value(Derived(TargetUri), request)
    == Ok("https://www.example.com/path?param=value")
}

pub fn authority_test() {
  let request = Request("GET", "https://www.example.com/path", [])
  assert component.component_value(Derived(Authority), request)
    == Ok("www.example.com")
}

pub fn authority_lowercases_host_test() {
  let request = Request("GET", "https://WWW.Example.COM/path", [])
  assert component.component_value(Derived(Authority), request)
    == Ok("www.example.com")
}

pub fn authority_strips_default_https_port_test() {
  let request = Request("GET", "https://example.com:443/", [])
  assert component.component_value(Derived(Authority), request)
    == Ok("example.com")
}

pub fn authority_strips_default_http_port_test() {
  let request = Request("GET", "http://example.com:80/", [])
  assert component.component_value(Derived(Authority), request)
    == Ok("example.com")
}

pub fn authority_keeps_non_default_port_test() {
  let request = Request("GET", "https://example.com:8443/", [])
  assert component.component_value(Derived(Authority), request)
    == Ok("example.com:8443")
}

pub fn scheme_test() {
  let request = Request("GET", "HTTPS://example.com/", [])
  assert component.component_value(Derived(Scheme), request) == Ok("https")
}

pub fn request_target_with_query_test() {
  let request = Request("POST", "https://www.example.com/path?param=value", [])
  assert component.component_value(Derived(RequestTarget), request)
    == Ok("/path?param=value")
}

pub fn request_target_without_query_test() {
  let request = Request("GET", "https://www.example.com/path", [])
  assert component.component_value(Derived(RequestTarget), request)
    == Ok("/path")
}

pub fn path_test() {
  let request = Request("GET", "https://www.example.com/path?param=value", [])
  assert component.component_value(Derived(Path), request) == Ok("/path")
}

pub fn path_empty_normalizes_to_slash_test() {
  let request = Request("GET", "https://www.example.com", [])
  assert component.component_value(Derived(Path), request) == Ok("/")
}

pub fn query_test() {
  let request =
    Request(
      "GET",
      "https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman",
      [],
    )
  assert component.component_value(Derived(Query), request)
    == Ok("?param=value&foo=bar&baz=bat%2Dman")
}

pub fn query_bare_string_test() {
  let request = Request("POST", "https://www.example.com/path?queryString", [])
  assert component.component_value(Derived(Query), request)
    == Ok("?queryString")
}

pub fn query_absent_test() {
  let request = Request("GET", "https://www.example.com/path", [])
  assert component.component_value(Derived(Query), request) == Ok("?")
}

pub fn query_param_test() {
  let request =
    Request(
      "GET",
      "https://www.example.com/path?param=value&foo=bar&baz=batman&qux=",
      [],
    )
  assert component.component_value(Derived(QueryParam("baz")), request)
    == Ok("batman")
  assert component.component_value(Derived(QueryParam("qux")), request)
    == Ok("")
  assert component.component_value(Derived(QueryParam("param")), request)
    == Ok("value")
}

pub fn query_param_not_found_test() {
  let request = Request("GET", "https://www.example.com/path?param=value", [])
  assert component.component_value(Derived(QueryParam("missing")), request)
    == Error(component.QueryParamNotFound("missing"))
}

pub fn query_param_repeated_name_not_included_test() {
  let request = Request("GET", "https://www.example.com/path?a=1&a=2", [])
  assert component.component_value(Derived(QueryParam("a")), request)
    == Error(component.QueryParamNotFound("a"))
}

pub fn query_param_plus_and_percent_decode_reencode_test() {
  let request =
    Request(
      "GET",
      "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something",
      [],
    )
  assert component.component_value(Derived(QueryParam("var")), request)
    == Ok("this%20is%20a%20big%0Amultiline%20value")
  assert component.component_value(Derived(QueryParam("bar")), request)
    == Ok("with%20plus%20whitespace")
  assert component.component_value(
      Derived(QueryParam("fa%C3%A7ade%22%3A%20")),
      request,
    )
    == Ok("something")
}

pub fn status_test() {
  let response = Response(200, [])
  assert component.component_value(Derived(Status), response) == Ok("200")
}

pub fn status_not_allowed_on_request_test() {
  let request = Request("GET", "https://example.com/", [])
  assert component.component_value(Derived(Status), request)
    == Error(NotAResponseComponent)
}

pub fn method_not_allowed_on_response_test() {
  let response = Response(200, [])
  assert component.component_value(Derived(Method), response)
    == Error(NotARequestComponent(Method))
}

pub fn header_field_test() {
  let request = Request("GET", "https://example.com/", [#("Date", "some-date")])
  assert component.component_value(Field("date"), request) == Ok("some-date")
}

pub fn header_field_case_insensitive_test() {
  let request = Request("GET", "https://example.com/", [#("DaTe", "value")])
  assert component.component_value(Field("date"), request) == Ok("value")
}

pub fn header_field_repeated_joins_with_comma_space_test() {
  let request =
    Request("GET", "https://example.com/", [
      #("Cache-Control", "max-age=60"),
      #("Cache-Control", "   must-revalidate"),
    ])
  assert component.component_value(Field("cache-control"), request)
    == Ok("max-age=60, must-revalidate")
}

pub fn header_field_not_found_test() {
  let request = Request("GET", "https://example.com/", [])
  assert component.component_value(Field("date"), request)
    == Error(component.HeaderNotFound("date"))
}

pub fn identifier_to_string_test() {
  assert component.identifier_to_string(Derived(Method)) == "\"@method\""
  assert component.identifier_to_string(Field("Date")) == "\"date\""
  assert component.identifier_to_string(Derived(QueryParam("baz")))
    == "\"@query-param\";name=\"baz\""
}

pub fn identifier_to_element_test() {
  assert component.identifier_to_element(Derived(Method))
    == Item(BareString("@method"), [])
  assert component.identifier_to_element(Derived(QueryParam("baz")))
    == Item(BareString("@query-param"), [Parameter("name", BareString("baz"))])
}

pub fn signature_base_rsa_pss_example_test() {
  // RFC 9421 §2.5 non-normative example (Figure 1).
  let request =
    Request("POST", "https://example.com/foo?param=Value&Pet=dog", [
      #("Host", "example.com"),
      #("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
      #("Content-Type", "application/json"),
      #(
        "Content-Digest",
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      ),
      #("Content-Length", "18"),
    ])

  let components = [
    Derived(Method),
    Derived(Authority),
    Derived(Path),
    Field("content-digest"),
    Field("content-length"),
    Field("content-type"),
  ]

  let signature_params_element =
    InnerList(list.map(components, component.identifier_to_element), [
      Parameter("created", Integer(1_618_884_473)),
      Parameter("keyid", BareString("test-key-rsa-pss")),
    ])

  let expected =
    "\"@method\": POST\n"
    <> "\"@authority\": example.com\n"
    <> "\"@path\": /foo\n"
    <> "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
    <> "\"content-length\": 18\n"
    <> "\"content-type\": application/json\n"
    <> "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-length\" \"content-type\");created=1618884473;keyid=\"test-key-rsa-pss\""

  assert component.signature_base(components, request, signature_params_element)
    == Ok(expected)
}
