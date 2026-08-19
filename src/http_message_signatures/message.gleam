//// The HTTP request/response being signed or verified.
////
//// This type has no dependency on any HTTP framework, so it can be built from
//// (or applied to) whatever request/response representation the caller's HTTP
//// stack uses.

/// A message to be signed or verified.
///
/// `target_uri` must be an absolute URI string, e.g.
/// `https://example.com/foo?a=1` — it is parsed on demand to derive the
/// `@authority`/`@scheme`/`@path`/`@query` components.
///
/// `headers` is an ordered assoc list of raw `(name, value)` pairs, one entry
/// per occurrence on the wire — a header repeated twice is two entries, not
/// one comma-joined string. Header values are assumed to already be unfolded
/// (no obs-fold handling; that is a wire-parsing concern out of scope for a
/// library that works on already-parsed messages). Header name matching is
/// case-insensitive.
pub type Message {
  Request(method: String, target_uri: String, headers: List(#(String, String)))
  Response(status: Int, headers: List(#(String, String)))
}
