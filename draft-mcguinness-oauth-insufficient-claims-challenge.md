---
title: "OAuth 2.0 Insufficient Claims Challenge for Token Exchange"
abbrev: "OAuth Claims Challenge"
category: std

docname: draft-mcguinness-oauth-insufficient-claims-challenge-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - oauth
 - token exchange
 - claims
 - assertion
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "mcguinness/draft-mcguinness-oauth-insufficient-claims-challenge"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC6749:
  RFC7519:
  RFC8174:
  RFC8259:
  RFC8693:

informative:
  RFC6750:
  RFC9396:
  RFC9470:
  I-D.ietf-oauth-identity-assertion-authz-grant:

  OpenID.Core:
    title: OpenID Connect Core 1.0 incorporating errata set 2
    target: https://openid.net/specs/openid-connect-core-1_0.html
    date: December 15, 2023
    author:
      - ins: N. Sakimura
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore

--- abstract

This specification defines a mechanism for an OAuth 2.0 Authorization
Server receiving a Token Exchange request to signal that the subject
token presented by the Client is otherwise acceptable but does not
contain the claims the Authorization Server requires to fulfil the
request. A new error code, `insufficient_claims`, together with a
`required_claims` response parameter, allows the Authorization Server
to enumerate the missing claims. A symmetric `required_claims` Token
Exchange request parameter allows the Client to forward those
requirements to the Authorization Server that issued the subject
token, so that a re-issued token can include the requested claims.
The mechanism is general to OAuth 2.0 Token Exchange. A motivating
use case is just-in-time account provisioning by a Resource
Authorization Server receiving an identity assertion under the
Identity Assertion Authorization Grant.


--- middle

# Introduction

OAuth 2.0 Token Exchange {{!RFC8693}} allows a Client to exchange one
security token for another. In many deployments, the Authorization
Server processing the Token Exchange request needs the subject token
to carry specific claims about the subject (for example, an
identifier, a directory attribute, or a policy attribute) in order to
fulfil the request. Without those claims the exchange cannot complete,
even though the subject token itself is cryptographically valid and of
an accepted type.

There is currently no interoperable way for the Authorization Server
processing the request to signal which claims are missing, nor for the
Client to convey that requirement to the Authorization Server that
issued the subject token. Coordination happens out of band per
deployment pair, which limits composability across Authorization
Servers, Clients, and resources.

This specification defines:

1. An OAuth 2.0 Token Exchange error code, `insufficient_claims`,
   returned by the Authorization Server processing the request when
   the subject token is otherwise acceptable but lacks claims required
   to fulfil it.

2. A `required_claims` error response parameter that enumerates the
   missing claims using the same syntax as the `scope` parameter
   ({{Section 3.3 of !RFC6749}}).

3. A `required_claims` Token Exchange request parameter that the
   Client forwards to the Authorization Server that issued the subject
   token, asking that the named claims be included in a re-issued
   token.

The mechanism is opt-in and degrades gracefully. The Processing
Authorization Server opts in by returning the `insufficient_claims`
error; a Client that does not recognize the error treats the response
as it would any other Token Exchange failure. An Issuing Authorization
Server that does not recognize the `required_claims` request parameter
ignores it per {{Section 3.2 of !RFC6749}} and processes the request
as it otherwise would; the Client may then receive a second
`insufficient_claims` response from the Processing Authorization
Server, which per {{no-loop}} it treats as a terminal failure. The
mechanism is compositional with existing claim-issuance policy: the
Issuing Authorization Server does not release any claim it would not
otherwise release, and remains the policy authority.

## Why a New Error Code

{{!RFC6749}} defines `invalid_grant` for tokens that are rejected.
{{?RFC6750}} defines `insufficient_scope`, returned by a protected
resource when a presented Access Token is otherwise valid but does not
carry sufficient `scope` to fulfil the request. {{?RFC9470}} defines
`insufficient_user_authentication`, returned by a protected resource
when an Access Token is otherwise valid but the authentication context
behind it is insufficient. The condition addressed here is parallel to
`insufficient_scope`: the subject token is cryptographically valid and
structurally acceptable, but the claim content it carries is
insufficient for the Authorization Server to fulfil the Token Exchange
request. A distinct error code lets the Client distinguish a
recoverable claim-negotiation failure from a hard rejection of the
subject token.

## Motivating Use Case

A common deployment pattern, formalized by the Identity Assertion
Authorization Grant {{?I-D.ietf-oauth-identity-assertion-authz-grant}},
uses Token Exchange to convey an identity assertion issued by an
Identity Provider (IdP) Authorization Server to a Resource
Authorization Server (RAS) governing a downstream resource. When the
subject does not yet have an account at the RAS, the RAS may perform
just-in-time (JIT) account provisioning using the claims in the
assertion; when the subject already has an account, the RAS may update
it from those claims. Either operation requires a sufficient set of
identity claims, and the required set varies per RAS. The mechanism
defined here allows the RAS to enumerate the claims it needs and the
Client to forward that requirement to the IdP Authorization Server.

Other use cases include any Token Exchange where the requested token
type or audience implies a claim contract the subject token does not
yet satisfy.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the following terms from {{!RFC6749}}: Client,
Authorization Server, Access Token, and error response.

This document uses the following terms from {{!RFC8693}}: Token
Exchange, subject token, and requested token type.

This document additionally uses the following terms:

Issuing Authorization Server:
: An OAuth 2.0 Authorization Server with which the Client has an
  established credential relationship and that can issue, via Token
  Exchange, a subject token of the type the Processing Authorization
  Server expects. The Issuing Authorization Server is the target of a
  Client's retry Token Exchange request containing the
  `required_claims` parameter.

Processing Authorization Server:
: The OAuth 2.0 Authorization Server that receives the Token Exchange
  request from the Client and decides whether to issue the requested
  token. The Processing Authorization Server is the originator of the
  `insufficient_claims` error response.

Claim:
: An attribute of the subject or the assertion, as defined in
  {{Section 4 of !RFC7519}} for JWT-formatted tokens and generalized
  here to any token format that carries named claims.


# Insufficient Claims Error Response

A Processing Authorization Server receiving a Token Exchange request
{{!RFC8693}} MUST first validate the subject token per its own
acceptance rules and the rules of the grant profile in use. If the
token is rejected for cryptographic, audience, issuer, type, or
freshness reasons, the server MUST respond with the applicable error
from {{Section 5.2 of !RFC6749}} (typically `invalid_grant`) rather
than the error defined here.

If the subject token is acceptable but does not carry claims
sufficient to fulfil the request, the Processing Authorization Server
MAY respond with the error code defined in this section.

## Error Code

The error code is:

`insufficient_claims`:
: The subject token presented in the Token Exchange request is
  acceptable but does not contain claims sufficient for the Processing
  Authorization Server to fulfil the request.

The error code is returned in the `error` parameter of the Token
Exchange error response, formatted per {{Section 5.2 of !RFC6749}}
with HTTP status code 400.

## required_claims Response Parameter

The error response SHOULD include a `required_claims` parameter
enumerating the claims the Processing Authorization Server requires.

The `required_claims` value is a string containing a space-delimited,
case-sensitive list of claim names. Each claim name is the name of a
claim as it would appear in the subject token (for example, `email`,
`name`, `given_name`, `family_name`). Claim names use the syntax of
`scope-token` from {{Section 3.3 of !RFC6749}}: each claim name MUST
consist only of characters in the ranges `%x21`, `%x23-5B`, and
`%x5D-7E`. In particular, claim names MUST NOT contain the SP
(`%x20`), DQUOTE (`%x22`), or backslash (`%x5C`) characters. The
order of names in the list is not significant.

When carried in a JSON error response body ({{!RFC8259}}), the value
is a JSON string. When carried as a form parameter in a Token Exchange
request (see {{request-param}}), the same syntactic value is encoded
per `application/x-www-form-urlencoded` rules; the surrounding JSON
quoting does not apply. Some registered JWT claim names are URIs and
contain characters such as `:` and `/`; these are permitted by the
`scope-token` syntax but MUST be percent-encoded when the value is
carried in a form-encoded body.

Example error response:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "insufficient_claims",
  "error_description": "The subject token is missing required claims.",
  "required_claims": "email given_name family_name"
}
~~~

The `required_claims` parameter is OPTIONAL. A Processing
Authorization Server that cannot or does not wish to enumerate the
missing claims MAY return the error code without it; in that case the
Client has no machine-readable basis for retry and SHOULD treat the
response as a terminal failure unless out-of-band information is
available.

A Processing Authorization Server MUST NOT include in
`required_claims` any claim name whose semantics are not defined by a
registered claims registry (such as the JSON Web Token Claims
registry), a registered profile (such as OpenID Connect Core
{{?OpenID.Core}}), or prior agreement with the population of Issuing
Authorization Servers it expects to interoperate with.

A Processing Authorization Server SHOULD NOT include the same claim
name more than once. A Client or Issuing Authorization Server
receiving duplicate claim names MUST treat the duplicates as a single
request for that claim.


# required_claims Token Exchange Request Parameter {#request-param}

A Client that receives an `insufficient_claims` error response from a
Processing Authorization Server, and that supports the mechanism
defined in this document, MAY send a Token Exchange request
{{!RFC8693}} to an Issuing Authorization Server, including the
`required_claims` parameter defined in this section, in order to
obtain a re-issued subject token.

The retry is a new Token Exchange request, not a repetition of any
prior request. The Client selects the `subject_token` and
`subject_token_type` based on its established credential relationship
with the Issuing Authorization Server; this is typically the same
`subject_token` the Client originally exchanged at that Authorization
Server. The Client MUST set the `audience` (and, if applicable,
`resource`) parameters to identify the same Processing Authorization
Server or resource as the original request.

A Client MUST ensure that the `required_claims` value it sends
conforms to the syntax defined in this document. If a value received
from a Processing Authorization Server is malformed, the Client MUST
NOT forward it as `required_claims`.

This document extends the Token Exchange request ({{Section 2.1 of
!RFC8693}}) with the following parameter:

`required_claims`:
: OPTIONAL. A space-delimited list of claim names that the Client is
  requesting be included in the issued token. The syntax is identical
  to the `required_claims` error response parameter defined in this
  document. When included in the Token Exchange request, the value is
  encoded as an `application/x-www-form-urlencoded` form parameter, as
  described by {{Section 2.1 of !RFC8693}}. The `required_claims`
  parameter MUST NOT appear more than once in a single Token Exchange
  request. A Client SHOULD NOT include the same claim name more than
  once within the value; an Issuing Authorization Server receiving
  duplicate claim names MUST treat them as a single request for that
  claim.

A Client SHOULD forward the `required_claims` value received in the
`insufficient_claims` error response verbatim, and MAY include
additional claim names based on local knowledge of the request.

Example request:

~~~ http
POST /oauth2/token HTTP/1.1
Host: issuer.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag
&subject_token=eyJhbGciOi...
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token
&audience=https%3A%2F%2Fapi.example.com%2F
&required_claims=email+given_name+family_name
~~~

## Issuing Authorization Server Behavior

An Issuing Authorization Server that supports the `required_claims`
parameter SHOULD attempt to include each requested claim in the issued
token, subject to its own policy. In particular, the Issuing
Authorization Server:

* MUST NOT release a claim it would not otherwise release under its
  configured policy for the requesting Client, the audience, and the
  subject. Receipt of `required_claims` is not authorization to bypass
  consent, privacy, or release controls.

* MUST NOT treat `required_claims` as a complete enumeration of the
  claims that should be issued. The Issuing Authorization Server MAY
  include additional claims it would normally include.

* MAY decline to include any specific requested claim. Declining to
  include a claim is not, by itself, a reason to fail the Token
  Exchange.

* SHOULD NOT fail the request because of an unrecognized claim name
  in `required_claims`.

Issuance of a token in response to a `required_claims` request is not
an assertion by the Issuing Authorization Server that all requested
claims were honored. A Client wishing to verify that a specific claim
is present in the re-issued token before retrying at the Processing
Authorization Server inspects the issued token using the mechanisms
applicable to its format.

## No Loop Guarantee {#no-loop}

This specification does not oblige the Issuing Authorization Server
to satisfy a `required_claims` request, nor the Processing
Authorization Server to accept a re-issued token whose claims still
fall short. For the purposes of this section, the "logical Token
Exchange" is the user-initiated workflow that produced the original
`insufficient_claims` response. A Client SHOULD issue at most one
retry per logical Token Exchange, and MUST treat any subsequent
`insufficient_claims` response for the same logical exchange as a
terminal failure, even if it enumerates a different `required_claims`
value.


# End-to-End Example

The following non-normative example illustrates the full exchange
using the Identity Assertion Authorization Grant profile
{{?I-D.ietf-oauth-identity-assertion-authz-grant}}, where the
Processing Authorization Server is the Resource Authorization Server
(RAS) and the Issuing Authorization Server is the Identity Provider
(IdP) Authorization Server.

~~~ aasvg
Client                IdP AS              RAS
   |                    |                  |
   |  TokenExchange     |                  |
   |  (subject=ID Token)|                  |
   |------------------->|                  |
   |                    |                  |
   |  Token (minimal)   |                  |
   |<-------------------|                  |
   |                    |                  |
   |  TokenExchange (subject=Token)        |
   |-------------------------------------->|
   |                    |                  |
   |     400 insufficient_claims           |
   |     required_claims="email            |
   |                      given_name       |
   |                      family_name"     |
   |<--------------------------------------|
   |                    |                  |
   |  TokenExchange     |                  |
   |  +required_claims  |                  |
   |------------------->|                  |
   |                    |                  |
   |  Token with        |                  |
   |  requested claims  |                  |
   |<-------------------|                  |
   |                    |                  |
   |  TokenExchange (subject=Token+)       |
   |-------------------------------------->|
   |                    |                  |
   |              200 OK { access_token }  |
   |<--------------------------------------|
~~~


# Relationship to Other Specifications

## Identity Assertion Authorization Grant

{{?I-D.ietf-oauth-identity-assertion-authz-grant}} defines the
`urn:ietf:params:oauth:token-type:id-jag` token type and the role of
the Resource Authorization Server in a cross-domain identity
assertion flow. With the mechanism defined here, specific claim
requirements at the RAS become a deployment-time decision negotiated
at runtime via `required_claims`, with the Issuing Authorization
Server retaining policy authority over release.

## OAuth 2.0 `scope` Parameter

The `scope` parameter ({{Section 3.3 of !RFC6749}}) is a coarse,
Authorization Server-specific authorization request signal. In some
deployment profiles, including OpenID Connect, specific scope values
(for example, `profile`, `email`) imply the issuance of specific
claims. This document does not redefine that mapping.

`required_claims` is finer-grained: a Processing Authorization Server
names individual claims directly, independent of any scope-to-claim
mapping the Issuing Authorization Server may apply. The Client can
forward a precise requirement without knowing that mapping.

`required_claims` complements `scope` rather than replacing it. A
Client retrying a Token Exchange request MAY include both parameters;
the Issuing Authorization Server applies its scope semantics as it
otherwise would, and additionally takes `required_claims` into
account.

## OpenID Connect `claims` Request Parameter

OpenID Connect Core 1.0 {{?OpenID.Core}} (Section 5.5) defines a
`claims` request parameter for use at the Authorization Endpoint and
the Token Endpoint, carrying a JSON object that requests individual
claims for the ID Token and UserInfo responses with optional
essential/voluntary semantics and value constraints.

This document does not reuse the OIDC `claims` parameter for the
following reasons:

* Encoding. OIDC `claims` carries a JSON object value inside a form
  parameter, requiring nested escaping and increasing request size.
  `required_claims` carries a flat list of names suitable for
  Token Exchange's `application/x-www-form-urlencoded` body and for a
  JSON error response body without nested encoding.

* Scope of effect. OIDC `claims` requests claims into specific
  OpenID-defined response artifacts (ID Token, UserInfo). The
  mechanism here requests claims into a Token Exchange-issued
  subject token of arbitrary `requested_token_type`, including
  non-OIDC types.

* Semantics. OIDC `claims` distinguishes essential and voluntary
  claims and allows value constraints. `required_claims` defers all
  such expressivity and treats every requested claim as advisory to
  the Issuing Authorization Server (see {{request-param}}). Profiles
  that need richer expressivity can define their own parameter.

An Authorization Server MAY support both `claims` and
`required_claims`. When both are present, the Authorization Server
processes each according to its defining specification; this document
does not define an interaction between them.

## OAuth 2.0 Rich Authorization Requests (RFC 9396)

{{?RFC9396}} carries structured request objects
(`authorization_details`) as JSON. `required_claims` is deliberately
flat: claim names are atomic tokens and do not require structured
encoding. Profiles needing per-claim value constraints or schema
references SHOULD define their own parameter rather than overload
`required_claims`.


# Security Considerations

## Disclosure of Claim Requirements

The `required_claims` error response parameter discloses to the
Client the set of claims the Processing Authorization Server intends
to consume. This is generally low-sensitivity information, comparable
to the OAuth `scope` parameter, but operators SHOULD confirm that
disclosing the list to any Client capable of reaching the Token
Exchange endpoint is acceptable.

## Disclosure of Issued Claims

When the Issuing Authorization Server includes additional claims in
the re-issued subject token in response to `required_claims`, those
claims may be readable by the Client (for example, a JWT-formatted
token can be parsed by anyone holding the token). Issuing
Authorization Servers SHOULD apply the same release policy as for any
other token issued to the same Client, audience, and subject. Where
the intended consumer is the Processing Authorization Server only and
the Client is treated as a transport, security guidance from
{{?I-D.ietf-oauth-identity-assertion-authz-grant}} on audience scoping
and (where supported) encryption of the token applies.

The Issuing Authorization Server is the policy authority for release.
Receipt of a `required_claims` parameter from a Client MUST NOT be
treated as user consent, subject release authorization, or any other
form of override of the Issuing Authorization Server's configured
policy. An Issuing Authorization Server that finds that satisfying
`required_claims` would violate policy MUST decline the affected
claims and MAY decline the request.

## Untrusted Input

A Processing Authorization Server constructing `required_claims`, and
an Issuing Authorization Server consuming it, MUST treat the
parameter value as untrusted input until validated. Implementations
MUST validate that each token in the list conforms to the syntax
constraints stated in this document and MUST NOT pass the value into
log formatters, database queries, or claim release rules without
proper escaping or parameterization.

## Replay and Caching

The error response and the `required_claims` parameter carry no
authentication state, no nonce, and no expiration, and MUST NOT be
used to make any access decision. They serve only to guide the
Client's next Token Exchange request. Responses carrying
`required_claims` SHOULD be returned with `Cache-Control: no-store`.

## Denial of Service

A Processing Authorization Server returning `insufficient_claims`
invites the Client to perform an additional Token Exchange request
against the Issuing Authorization Server. Implementations on both
sides SHOULD apply standard rate limiting to protect their Token
Exchange endpoints. As noted in {{no-loop}}, Clients SHOULD NOT retry
indefinitely.

## Trust Between Processing and Issuing Authorization Servers

This specification does not establish trust between the Processing
and Issuing Authorization Servers. The Client mediates between them
and can add, remove, or modify `required_claims` values. For this
reason `required_claims` is advisory: the Issuing Authorization
Server SHOULD evaluate the request against the Client's identity,
the requested audience, and its local release policy. It MUST NOT
infer a Processing Authorization Server requirement from
`required_claims` alone, nor treat the parameter's presence as
authorization to release any claim.


# Privacy Considerations

The mechanism in this document is designed to reduce, not increase,
claim disclosure relative to a static policy. Without
`required_claims`, an Issuing Authorization Server that wishes to
interoperate with multiple Processing Authorization Servers must
either include claims speculatively (releasing data that may not be
needed) or omit them and break the downstream operation. With
`required_claims`, an Issuing Authorization Server can release claims
only when a specific exchange requires them, subject to its own
policy.

Operators of Processing Authorization Servers SHOULD request the
minimum set of claims necessary, and SHOULD NOT enumerate claims they
do not consume.

Operators of Issuing Authorization Servers SHOULD apply consent,
contractual, or regulatory release controls before honoring any
specific entry in `required_claims`.


# IANA Considerations

## OAuth Extensions Error Registry

IANA is requested to add the following entry to the "OAuth Extensions
Error" registry established by {{Section 11.4 of !RFC6749}}.

Name:
: `insufficient_claims`

Usage Location:
: Token Error Response

Protocol Extension:
: This document

Change Controller:
: IETF

Specification Document(s):
: This document

Description:
: Indicates that the subject token presented in an OAuth 2.0 Token
  Exchange request is acceptable but does not contain claims
  sufficient for the Processing Authorization Server to fulfil the
  request.

## OAuth Parameters Registry

IANA is requested to add the following entry to the "OAuth Parameters"
registry established by {{Section 11.2 of !RFC6749}}.

### required_claims

Name:
: `required_claims`

Parameter Usage Location:
: token request, token response

Change Controller:
: IETF

Specification Document(s):
: This document


--- back

# Acknowledgments
{:numbered="false"}

The author thanks the OAuth working group participants who raised the
underlying interoperability gap in the Identity Assertion
Authorization Grant draft, in particular Aaron Parecki, Max Stytch,
and Meghna Dubey.
