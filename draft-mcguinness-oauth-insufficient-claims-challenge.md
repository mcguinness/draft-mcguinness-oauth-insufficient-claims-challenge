---
title: "OAuth 2.0 Insufficient Claims Challenge"
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
 - bearer
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
  RFC6750:
  RFC7521:
  RFC8174:
  RFC8259:
  RFC8693:

informative:
  RFC7519:
  RFC7522:
  RFC7523:
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
Server or Protected Resource to signal that a credential presented by
a Client is otherwise acceptable but does not carry the claims the
recipient requires to fulfil the request. A new error code,
`insufficient_claims`, together with a `required_claims` parameter
enumerating the missing claims, lets the recipient challenge the
Client to obtain a credential carrying those claims. The mechanism
applies to credentials presented at the OAuth 2.0 Token Endpoint by
assertion-based grants, including OAuth 2.0 Token Exchange, and to
Access Tokens presented at OAuth 2.0 Protected Resources. A motivating
use case is just-in-time account provisioning by a Resource
Authorization Server receiving an identity assertion under the
Identity Assertion Authorization Grant.


--- middle

# Introduction

OAuth 2.0 deployments routinely pass credentials between system
components. A Client presents an assertion or subject token at the
Authorization Server's Token Endpoint to obtain an Access Token; a
Client then presents that Access Token at a Protected Resource to
invoke an operation. In each case the recipient may require specific
claims about the subject -- an identifier, a directory attribute, or a
policy attribute -- and the credential it receives may not carry
them. Without those claims the operation cannot complete, even though
the credential itself is cryptographically valid and structurally
acceptable.

There is currently no interoperable way for either an Authorization
Server processing a Token Endpoint request, or a Protected Resource
processing a resource request, to signal which claims are missing, or
for the Client to convey that requirement to whoever issued the
credential. Coordination happens out of band per deployment pair,
which limits composability across Authorization Servers, Clients, and
resources.

This specification defines:

1. An OAuth 2.0 error code, `insufficient_claims`, returned by the
   recipient of a credential when that credential is otherwise
   acceptable but lacks claims required to fulfil the request. The
   error code is returned in Token Endpoint error responses
   ({{Section 5.2 of RFC6749}}) for any assertion-based grant
   ({{RFC7521}}) or Token Exchange ({{RFC8693}}), and in Bearer
   authentication challenges at Protected Resources
   ({{Section 3 of RFC6750}}).

2. A `required_claims` parameter that enumerates the missing claims
   using the same syntax as the `scope` parameter
   ({{Section 3.3 of RFC6749}}). The parameter is carried in the
   error response or challenge.

3. A `required_claims` Token Endpoint request parameter that a Client
   includes when retrying via Token Exchange with the Authorization
   Server that issued the subject token, in order to obtain a
   re-issued subject token carrying the requested claims. This retry
   parameter is defined for OAuth 2.0 Token Exchange only; for other
   assertion-based grants, the error code still applies but the
   mechanism by which the Client obtains a richer assertion is
   grant-specific and out of scope.

The mechanism is opt-in and degrades gracefully. A recipient opts in
by returning `insufficient_claims`; a Client that does not recognize
the error treats the response as it would any other failure. An
Authorization Server that does not recognize the `required_claims`
request parameter ignores it per {{Section 3.2 of RFC6749}}; the
Client may then receive a second `insufficient_claims`, which per
{{no-loop}} it treats as a terminal failure. The mechanism is
compositional with existing claim-issuance policy: an Authorization
Server does not release any claim it would not otherwise release, and
remains the policy authority.

## Why a New Error Code

{{RFC6749}} defines `invalid_grant` for tokens that are rejected.
{{RFC6750}} defines `insufficient_scope`, returned by a Protected
Resource when a presented Access Token is otherwise valid but does
not carry sufficient `scope`. {{RFC9470}} defines
`insufficient_user_authentication`, returned by a Protected Resource
when an Access Token is otherwise valid but the authentication
context behind it is insufficient. The condition addressed here is
parallel to `insufficient_scope` but applies to claim content rather
than scope, and applies at both the Token Endpoint and the Protected
Resource. A distinct error code lets the Client distinguish a
recoverable claim-negotiation failure from a hard rejection of the
credential.

## Motivating Use Cases

### Just-in-Time Account Provisioning at a Resource Authorization Server

A common deployment pattern, formalized by the Identity Assertion
Authorization Grant {{I-D.ietf-oauth-identity-assertion-authz-grant}},
uses Token Exchange to convey an identity assertion issued by an
Identity Provider (IdP) Authorization Server to a Resource
Authorization Server (RAS) governing a downstream resource. When the
subject does not yet have an account at the RAS, the RAS may perform
just-in-time (JIT) account provisioning using the claims in the
assertion; when the subject already has an account, the RAS may
update it from those claims. Either operation requires a sufficient
set of identity claims, and the required set varies per RAS. The
mechanism defined here allows the RAS to enumerate the claims it
needs and the Client to forward that requirement to the IdP
Authorization Server.

### Resource-Side Claim Requirements

A Protected Resource may require subject claims at request time that
were not provisioned into the Access Token at issuance: for example,
an authorization service whose policy depends on attributes the
Client did not request via `scope`, or a downstream resource that
needs claims an upstream Authorization Server did not include. The
mechanism defined here allows the Protected Resource to challenge the
Client to obtain a richer Access Token before retrying.

### Other Assertion-Based Grants

Any assertion-based grant defined by {{RFC7521}}, including JWT
Bearer ({{RFC7523}}) and SAML 2.0 Bearer ({{RFC7522}}), shares the
"incoming credential carrying claims" shape with Token Exchange.
This specification's error code applies uniformly to those grants;
how the Client obtains a richer assertion is grant-specific.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the following terms from {{RFC6749}}: Client,
Authorization Server, Access Token, Token Endpoint, Protected
Resource, and error response.

This document uses the following terms from {{RFC8693}}: Token
Exchange, subject token, and requested token type.

This document uses the term "assertion" as defined in
{{Section 1.2 of RFC7521}}: a package of information that allows
identity and security information to be shared across security
domains.

This document additionally uses the following terms:

Issuing Authorization Server:
: An OAuth 2.0 Authorization Server with which the Client has an
  established credential relationship and that issued, or can
  re-issue, a credential the Client uses in an OAuth 2.0 request.
  In the Token Exchange retry case ({{request-param}}) this is the
  Authorization Server the Client targets with `required_claims`;
  in the Protected Resource case ({{resource}}) this is the
  Authorization Server that issued the Access Token presented at the
  resource.

Processing Authorization Server:
: The OAuth 2.0 Authorization Server that receives a Token Endpoint
  request from the Client and decides whether to issue the requested
  token. The Processing Authorization Server is the originator of an
  `insufficient_claims` error response at the Token Endpoint.

Claim:
: An attribute of the subject or the assertion, as defined in
  {{Section 4 of RFC7519}} for JWT-formatted tokens and generalized
  here to any token format that carries named claims.


# Insufficient Claims at the Token Endpoint {#token-endpoint}

This section applies to Token Endpoint requests that use an
assertion-based grant ({{RFC7521}}, including JWT Bearer ({{RFC7523}})
and SAML 2.0 Bearer ({{RFC7522}})) or OAuth 2.0 Token Exchange
({{RFC8693}}). The error code defined in {{error-code}} applies to
all such grants. The `required_claims` request parameter defined in
{{request-param}} is defined only for the Token Exchange retry path;
for other assertion-based grants, the Client obtains a richer
assertion using grant-specific mechanisms outside this document's
scope.

A Processing Authorization Server receiving such a request MUST first
validate the assertion or subject token per its own acceptance rules
and the rules of the grant profile in use. If the credential is
rejected for cryptographic, audience, issuer, type, or freshness
reasons, the server MUST respond with the applicable error from
{{Section 5.2 of RFC6749}} (typically `invalid_grant`) rather than
the error defined here.

If the assertion or subject token is acceptable but does not carry
claims sufficient to fulfil the request, the Processing Authorization
Server MAY respond with the error code defined in this section.

## Error Code {#error-code}

The error code is:

`insufficient_claims`:
: The credential presented in the Token Endpoint request is
  acceptable but does not carry claims sufficient for the Processing
  Authorization Server to fulfil the request.

The error code is returned in the `error` parameter of the Token
Endpoint error response, formatted per {{Section 5.2 of RFC6749}}
with HTTP status code 400.

## required_claims Response Parameter {#response-param}

The error response SHOULD include a `required_claims` parameter
enumerating the claims the Processing Authorization Server requires.

The `required_claims` value is a string containing a space-delimited,
case-sensitive list of claim names. Each claim name is the name of a
claim as it would appear in the credential (for example, `email`,
`name`, `given_name`, `family_name`). Claim names use the syntax of
`scope-token` from {{Section 3.3 of RFC6749}}: each claim name MUST
consist only of characters in the ranges `%x21`, `%x23-5B`, and
`%x5D-7E`. In particular, claim names MUST NOT contain the SP
(`%x20`), DQUOTE (`%x22`), or backslash (`%x5C`) characters. The
order of names in the list is not significant.

When carried in a JSON error response body ({{RFC8259}}), the value
is a JSON string. When carried as a form parameter in a Token
Endpoint request (see {{request-param}}), the same syntactic value
is encoded per `application/x-www-form-urlencoded` rules; the
surrounding JSON quoting does not apply. Some registered JWT claim
names are URIs and contain characters such as `:` and `/`; these are
permitted by the `scope-token` syntax but MUST be percent-encoded
when the value is carried in a form-encoded body.

Example error response:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "insufficient_claims",
  "error_description": "The presented credential is missing required claims.",
  "required_claims": "email given_name family_name"
}
~~~

The `required_claims` parameter is OPTIONAL. A Processing
Authorization Server that cannot or does not wish to enumerate the
missing claims MAY return the error code without it; in that case
the Client has no machine-readable basis for retry and SHOULD treat
the response as a terminal failure unless out-of-band information is
available.

A Processing Authorization Server MUST NOT include in
`required_claims` any claim name whose semantics are not defined by
a registered claims registry (such as the JSON Web Token Claims
registry), a registered profile (such as OpenID Connect Core
{{OpenID.Core}}), or prior agreement with the population of Issuing
Authorization Servers it expects to interoperate with.

A Processing Authorization Server SHOULD NOT include the same claim
name more than once. A Client or Issuing Authorization Server
receiving duplicate claim names MUST treat the duplicates as a
single request for that claim.

## required_claims Token Endpoint Request Parameter {#request-param}

A Client that receives an `insufficient_claims` error response from
a Processing Authorization Server, and that supports the mechanism
defined in this document, MAY send a Token Exchange request
({{RFC8693}}) to an Issuing Authorization Server, including the
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

This document extends the Token Endpoint request ({{Section 3.2 of
RFC6749}}) with the following parameter:

`required_claims`:
: OPTIONAL. A space-delimited list of claim names that the Client is
  requesting be included in the issued token. The syntax is
  identical to the `required_claims` error response parameter
  defined in this document. When included in a Token Endpoint
  request, the value is encoded as an
  `application/x-www-form-urlencoded` form parameter. The
  `required_claims` parameter MUST NOT appear more than once in a
  single Token Endpoint request. A Client SHOULD NOT include the
  same claim name more than once within the value; an Authorization
  Server receiving duplicate claim names MUST treat them as a single
  request for that claim.

A Client SHOULD forward the `required_claims` value received in the
`insufficient_claims` error response verbatim, and MAY include
additional claim names based on local knowledge of the target
resource.

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

The `required_claims` request parameter is defined for use with
OAuth 2.0 Token Exchange. For other assertion-based grants
({{RFC7521}}, {{RFC7522}}, {{RFC7523}}), the mechanism by which the
Client obtains a richer assertion is grant-specific and out of scope
for this document; the Client uses whatever process its assertion
provider supports and then presents the resulting assertion in a
fresh Token Endpoint request.

## Authorization Server Behavior

An Authorization Server that supports the `required_claims` request
parameter SHOULD include each requested claim in the issued token,
subject to its own policy. In particular, the Authorization Server:

* MUST NOT release a claim it would not otherwise release under its
  configured policy for the requesting Client, the audience, and
  the subject. Receipt of `required_claims` is not authorization to
  bypass consent, privacy, or release controls.

* MUST NOT treat `required_claims` as a complete enumeration of the
  claims that should be issued. The Authorization Server MAY include
  additional claims it would normally include.

* MAY decline to include any specific requested claim. Declining to
  include a claim is not, by itself, a reason to fail the request.

* SHOULD NOT fail the request because of an unrecognized claim name
  in `required_claims`.

Issuance of a token in response to a `required_claims` request is
not an assertion by the Authorization Server that all requested
claims were honored. A Client wishing to verify that a specific
claim is present in the re-issued token before retrying inspects the
issued token using the mechanisms applicable to its format.

## No Loop Guarantee {#no-loop}

This specification does not oblige the Issuing Authorization Server
to satisfy a `required_claims` request, nor the Processing
Authorization Server to accept a re-issued credential whose claims
still fall short. For the purposes of this section, the "logical
Token Endpoint exchange" is the user-initiated workflow that
produced the original `insufficient_claims` response. A Client
SHOULD issue at most one retry per logical Token Endpoint exchange,
and MUST treat any subsequent `insufficient_claims` response for the
same logical exchange as a terminal failure, even if it enumerates a
different `required_claims` value.


# Insufficient Claims at the Protected Resource {#resource}

When a Protected Resource receives a request bearing an Access Token
that is otherwise valid but does not carry claims sufficient to
fulfil the request, the Protected Resource MAY return an
authentication challenge containing the `insufficient_claims` error
code.

The challenge follows {{Section 3 of RFC6750}}. The Protected
Resource MUST respond with HTTP status 403 Forbidden and a
`WWW-Authenticate` header field that includes the `error` parameter
with the value `insufficient_claims`. The challenge SHOULD include a
`required_claims` parameter enumerating the claims the Protected
Resource requires; the parameter has the syntax defined in
{{response-param}}.

The HTTP status code is 403 Forbidden, consistent with
`insufficient_scope` ({{Section 3.1 of RFC6750}}): the Access Token
authenticates the Client and subject but does not authorize this
specific request because of insufficient claim content. The 401
Unauthorized status code is not used because the issue is not
authentication of the Client or the token.

Example challenge (line breaks added for readability):

~~~ http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="example",
                  error="insufficient_claims",
                  error_description="The presented Access Token is missing required claims.",
                  required_claims="email department"
~~~

If the resource request was unauthenticated (no Access Token
presented), the Protected Resource MUST use the existing error
semantics of {{Section 3 of RFC6750}} (no `error` parameter or
`error="invalid_token"`), not `insufficient_claims`. The error
defined here is only applicable when the presented Access Token is
otherwise acceptable.

## Client Behavior

A Client that receives an `insufficient_claims` challenge from a
Protected Resource, and that supports the mechanism defined in this
document, obtains a new Access Token carrying the claims indicated by
`required_claims` and retries the resource request with the new
token. The mechanism by which the Client obtains the new Access
Token depends on its grant:

* When the Access Token was obtained via Token Exchange, the Client
  MAY include the `required_claims` request parameter
  ({{request-param}}) in a fresh Token Exchange.

* When the Access Token was obtained via another assertion-based
  grant, the Client uses whatever mechanism its Authorization Server
  supports to obtain a richer Access Token, including (where
  applicable) the `required_claims` request parameter.

* When the Access Token was obtained via an interactive
  authorization flow, the Client MAY initiate a new authorization
  request using the `claims` request parameter of OpenID Connect
  Core 1.0 {{OpenID.Core}} (where applicable) or other deployment-
  specific mechanisms to obtain an Access Token carrying the
  requested claims.

A Client SHOULD issue at most one retry per resource request in
response to `insufficient_claims`, and MUST treat any subsequent
`insufficient_claims` challenge for the same logical request as a
terminal failure to avoid retry loops.

# End-to-End Examples

## Token Exchange Retry

The following non-normative example illustrates the Token Endpoint
flow using the Identity Assertion Authorization Grant profile
({{I-D.ietf-oauth-identity-assertion-authz-grant}}), where the
Processing Authorization Server is the Resource Authorization Server
(RAS) and the Issuing Authorization Server is the Identity Provider
(IdP) Authorization Server.

~~~ ascii-art
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

## Protected Resource Challenge

The following non-normative example illustrates a Protected Resource
returning `insufficient_claims` and the Client obtaining a richer
Access Token via Token Exchange before retrying.

~~~ ascii-art
Client                  AS                Resource
   |                    |                    |
   |  GET /api/foo                           |
   |  Authorization: Bearer AT1              |
   |---------------------------------------->|
   |                    |                    |
   |  403 Forbidden                          |
   |  WWW-Authenticate: Bearer               |
   |    error="insufficient_claims",         |
   |    required_claims="email department"   |
   |<----------------------------------------|
   |                    |                    |
   |  TokenExchange     |                    |
   |  +required_claims  |                    |
   |------------------->|                    |
   |                    |                    |
   |  AT2 (carries     |                    |
   |  email, department)|                    |
   |<-------------------|                    |
   |                    |                    |
   |  GET /api/foo                           |
   |  Authorization: Bearer AT2              |
   |---------------------------------------->|
   |                    |                    |
   |              200 OK { result }          |
   |<----------------------------------------|
~~~


# Relationship to Other Specifications

## Identity Assertion Authorization Grant

{{I-D.ietf-oauth-identity-assertion-authz-grant}} defines the
`urn:ietf:params:oauth:token-type:id-jag` token type and the role of
the Resource Authorization Server in a cross-domain identity
assertion flow. With the mechanism defined here, specific claim
requirements at the RAS become a deployment-time decision negotiated
at runtime via `required_claims`, with the Issuing Authorization
Server retaining policy authority over release.

## Assertion-Based Grants (RFC 7521, RFC 7522, RFC 7523)

{{RFC7521}} defines the framework for assertion-based OAuth 2.0
grants; {{RFC7522}} and {{RFC7523}} define specific profiles for
SAML 2.0 and JWT assertions respectively. The `insufficient_claims`
error code defined here applies uniformly to Token Endpoint requests
using any of these grants. The `required_claims` request parameter
({{request-param}}) is defined for the Token Exchange retry case;
for other assertion-based grants, the Client obtains a richer
assertion using whatever mechanism its assertion provider supports.

## OAuth 2.0 `scope` Parameter

The `scope` parameter ({{Section 3.3 of RFC6749}}) is a coarse,
Authorization Server-specific authorization request signal. In some
deployment profiles, including OpenID Connect, specific scope values
(for example, `profile`, `email`) imply the issuance of specific
claims. This document does not redefine that mapping.

`required_claims` is finer-grained: a recipient names individual
claims directly, independent of any scope-to-claim mapping the
issuing Authorization Server may apply. The Client can forward a
precise requirement without knowing that mapping.

`required_claims` complements `scope` rather than replacing it. A
Client retrying at the Token Endpoint MAY include both parameters;
the Authorization Server applies its scope semantics as it otherwise
would, and additionally takes `required_claims` into account.

## OpenID Connect `claims` Request Parameter

OpenID Connect Core 1.0 {{OpenID.Core}} (Section 5.5) defines a
`claims` request parameter for use at the Authorization Endpoint and
the Token Endpoint, carrying a JSON object that requests individual
claims for the ID Token and UserInfo responses with optional
essential/voluntary semantics and value constraints.

This document does not reuse the OIDC `claims` parameter for the
following reasons:

* Encoding. OIDC `claims` carries a JSON object value inside a form
  parameter, requiring nested escaping and increasing request size.
  `required_claims` carries a flat list of names suitable for a
  Token Endpoint `application/x-www-form-urlencoded` body, a JSON
  error response body, and a `WWW-Authenticate` challenge.

* Scope of effect. OIDC `claims` requests claims into specific
  OpenID-defined response artifacts (ID Token, UserInfo).
  `required_claims` requests claims into any issued token
  (Access Token, Token Exchange-issued subject token), including
  non-OIDC types.

* Semantics. OIDC `claims` distinguishes essential and voluntary
  claims and allows value constraints. `required_claims` defers all
  such expressivity and treats every requested claim as advisory to
  the Authorization Server. Profiles that need richer expressivity
  can define their own parameter.

An Authorization Server MAY support both `claims` and
`required_claims`. When both are present, the Authorization Server
processes each according to its defining specification; this
document does not define an interaction between them.

A Client that receives an `insufficient_claims` challenge at a
Protected Resource (see {{resource}}) and that originally obtained
its Access Token via an OpenID Connect Authorization Endpoint flow
MAY use the OIDC `claims` request parameter to obtain a richer
Access Token, as described in {{resource}}.

## OAuth 2.0 Bearer Token Usage (RFC 6750) and Step-Up Authentication (RFC 9470)

{{RFC6750}} defines the Bearer authentication scheme used at the
Protected Resource and the `insufficient_scope` error returned when
the Access Token's scope is insufficient. {{RFC9470}} defines
`insufficient_user_authentication` returned when the authentication
context behind the Access Token is insufficient. The mechanism in
{{resource}} of this document follows the same challenge pattern
but addresses claim content rather than scope or authentication
context.

## OAuth 2.0 Rich Authorization Requests (RFC 9396)

{{RFC9396}} carries structured request objects
(`authorization_details`) as JSON. `required_claims` is deliberately
flat: claim names are atomic tokens and do not require structured
encoding. Profiles needing per-claim value constraints or schema
references SHOULD define their own parameter rather than overload
`required_claims`.


# Security Considerations

## Disclosure of Claim Requirements

The `required_claims` parameter in an error response or
authentication challenge discloses to the Client the set of claims
the recipient intends to consume. This is generally low-sensitivity
information, comparable to the OAuth `scope` parameter, but
operators SHOULD confirm that disclosing the list to any Client
capable of reaching the Token Endpoint or Protected Resource is
acceptable.

## Disclosure of Issued Claims

When an Authorization Server includes additional claims in a
re-issued token in response to `required_claims`, those claims may
be readable by the Client (for example, a JWT-formatted token can
be parsed by anyone holding the token). Authorization Servers SHOULD
apply the same release policy as for any other token issued to the
same Client, audience, and subject. Where the intended consumer is
the recipient only and the Client is treated as a transport,
security guidance from {{I-D.ietf-oauth-identity-assertion-authz-grant}}
on audience scoping and (where supported) encryption of the token
applies.

The Authorization Server is the policy authority for release.
Receipt of a `required_claims` parameter from a Client MUST NOT be
treated as user consent, subject release authorization, or any other
form of override of the Authorization Server's configured policy. An
Authorization Server that finds that satisfying `required_claims`
would violate policy MUST decline the affected claims and MAY
decline the request.

## Untrusted Input

A recipient constructing `required_claims`, and an Authorization
Server consuming it, MUST treat the parameter value as untrusted
input until validated. Implementations MUST validate that each
token in the list conforms to the syntax constraints stated in this
document and MUST NOT pass the value into log formatters, database
queries, or claim release rules without proper escaping or
parameterization.

## Replay and Caching

The error response, the authentication challenge, and the
`required_claims` parameter carry no authentication state, no
nonce, and no expiration, and MUST NOT be used to make any access
decision. They serve only to guide the Client's next request. Token
Endpoint responses carrying `required_claims` SHOULD be returned
with `Cache-Control: no-store`.

## Denial of Service

A recipient returning `insufficient_claims` invites the Client to
perform an additional Token Endpoint request against an
Authorization Server. Implementations on all sides SHOULD apply
standard rate limiting to protect their endpoints. As noted in
{{no-loop}} and {{resource}}, Clients SHOULD NOT retry indefinitely.

## Trust Between Recipient and Issuing Authorization Server

This specification does not establish trust between a recipient
(Processing Authorization Server or Protected Resource) and the
Issuing Authorization Server. The Client mediates between them and
can add, remove, or modify `required_claims` values. For this
reason `required_claims` is advisory: the Issuing Authorization
Server SHOULD evaluate the request against the Client's identity,
the requested audience, and its local release policy. It MUST NOT
infer a recipient requirement from `required_claims` alone, nor
treat the parameter's presence as authorization to release any
claim.


# Privacy Considerations

The mechanism in this document is designed to reduce, not increase,
claim disclosure relative to a static policy. Without
`required_claims`, an Issuing Authorization Server that wishes to
interoperate with multiple recipients must either include claims
speculatively (releasing data that may not be needed) or omit them
and break the downstream operation. With `required_claims`, an
Authorization Server can release claims only when a specific
exchange requires them, subject to its own policy.

Operators of recipients (Processing Authorization Servers and
Protected Resources) SHOULD request the minimum set of claims
necessary, and SHOULD NOT enumerate claims they do not consume.

Operators of Issuing Authorization Servers SHOULD apply consent,
contractual, or regulatory release controls before honoring any
specific entry in `required_claims`.


# IANA Considerations

## OAuth Extensions Error Registry

IANA is requested to add the following entry to the "OAuth Extensions
Error" registry established by {{Section 11.4 of RFC6749}}.

Name:
: `insufficient_claims`

Usage Location:
: Token Error Response, Resource Access Error Response

Protocol Extension:
: This document

Change Controller:
: IETF

Specification Document(s):
: This document

Description:
: Indicates that the credential presented by the Client is acceptable
  but does not carry claims sufficient for the recipient to fulfil
  the request. Returned in OAuth 2.0 Token Endpoint error responses
  and in OAuth 2.0 Bearer authentication challenges at Protected
  Resources.

## OAuth Parameters Registry

IANA is requested to add the following entry to the "OAuth
Parameters" registry established by {{Section 11.2 of RFC6749}}.

Name:
: `required_claims`

Parameter Usage Location:
: token request, token response, resource access authentication challenge

Change Controller:
: IETF

Specification Document(s):
: This document


--- back

# Acknowledgments
{:numbered="false"}

The author thanks the OAuth working group participants who raised
the underlying interoperability gap in the Identity Assertion
Authorization Grant draft, in particular Aaron Parecki, Max Stytch,
and Meghna Dubey.
