# EasyList matching profile

Profile `abp-core-0.11.1-network-v1` targets network decisions against the fixed
Adblock Plus core commit in `tools/reference-lock.json`. This is a matching
library with CLI inputs, not a browser implementation.

Input JSON requires `url`, `resource_type` and `document_url`. Optional
`ancestors` lists the immediate document's parent through the top-level page,
nearest first, with at most 16 entries. An empty list means the caller declares
the supplied document top-level. Missing mandatory context is an error.

Types are other, script, image, stylesheet, object, subdocument, websocket,
webrtc, ping, xmlhttprequest, media, font, popup and document. Default filters
match resource types, excluding popup and document. Type options and their
negations follow the pinned parser's order. Background, xbl and dtd are aliases.

The rule parser supports URL substrings, wildcards, start/end/domain anchors,
separator-or-end, `@@`, match-case, domain inclusion/exclusion and third-party.
Domain decisions use the most specific matching suffix. A positive domain makes
the filter specific, while exclusions alone leave it generic. The fixed public
suffix snapshot determines first/third-party, including private suffix entries.
Address-shaped IP hostnames use exact domain matches. Numeric suffixes such as
`0.1` do not constrain `127.0.0.1`. IPv6 domain options are supported. An include
followed by an exclusion of the same domain still disables the default domain,
as in the pinned matcher. Trailing dots in filter domain options are preserved.

Explicit request exceptions or any matching document allowlist return ALLOW.
Otherwise a specific block or an unsuppressed generic block returns BLOCK.
Otherwise return NOMATCH. A matching `$genericblock` exception on the supplied
document chain suppresses generic blocks only. The compiler implements this
policy before garbling, and does not send per-rule results to the client.

Patterns are matched against ASCII URL serialization. The caller may provide
Unicode hostnames, which are IDNA encoded, and Unicode path/query characters,
which are UTF-8 percent encoded. Scheme/host are canonicalized and default ports
removed, while path/query case is preserved. Only absolute http/https/ws/wss
URLs are accepted. Credentials, backslashes and literal control bytes require
caller normalization or are rejected. Scoped IPv6 and empty hostname labels are
also rejected. This deliberately defined serialization
does not implement the entire WHATWG/browser URL parser. The same serialized
URL is passed to the independent matcher in differential tests.

Encoding is `Z2`, followed by one request frame, one or more document frames,
then EOS byte 3. Each frame is kind byte, type byte, party byte, ASCII document
hostname, delimiter byte 0, URL-start byte 4, ASCII URL, delimiter byte 0.
Request kind is 1 and document kind is 2. Type codes begin at 128, and party is
16 or 17. URL serialization cannot contain these literal control delimiters.
The encoded length is public n. No URL truncation or silent default type exists.

Cosmetic/DOM/scriptlet rules and browser actions including CSP, rewrite and
header handling are recorded as out_of_scope. Cosmetic-only allowlisting flags
are also out_of_scope. Unknown options and unsupported regular expressions are
explicit errors. Regex compiler coverage is checked separately from lexical
parsing so an accepted regex cannot silently fall back to plaintext evaluation.

On 2026-10-04, the local `rules/easylist.txt` snapshot parsed into 47,154 supported
network candidates, 23,813 out-of-scope lines and 299 metadata/blank lines, with
no parser-invalid or unknown-option lines. This is parser coverage, not a claim
that its entire DFA fits the selected resource bounds. The snapshot SHA256 is
`2888c230ef758e3c5c73a867376ed379d12cd2e9d9b94551634fc60dc1a05f34`.

Run `uv run --locked python tools/setup_reference.py` once to install the pinned reference into
ignored `.reference/abp`. It verifies the archive digest and does not run npm
install scripts. `node tools/reference_matcher.cjs` reads rules/context JSON on
stdin and returns decisions only for offline testing. It never fetches a URL.
