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
  RFC8414:
  RFC8693:
  RFC9728:

informative:
  RFC7519:
  RFC7522:
  RFC7523:
  RFC8707:
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

This specification defines an OAuth 2.0 challenge mechanism by which
an Authorization Server or Protected Resource signals that a
credential presented by a Client is otherwise acceptable but does not
carry the claims the recipient requires to fulfil the request. A new
error code, `insufficient_claims`, together with a `required_claims`
parameter that enumerates the missing claims, lets the recipient
indicate which claims are needed. The same challenge is used in
Token Endpoint error responses, in Bearer authentication challenges
at Protected Resources, and (optionally) in OAuth 2.0 Protected
Resource Metadata. The challenge is intentionally decoupled from how
the Client responds: for back-channel re-issuance grants (OAuth 2.0
Token Exchange and Refresh Token), a Client uses the `requested_claims`
Token Endpoint request parameter defined here; for grants that may
require end-user interaction (authorization_code, device_code, CIBA),
a Client uses the OpenID Connect `claims` request parameter. A
motivating use case is just-in-time account provisioning by a
Resource Authorization Server receiving an identity assertion under
the Identity Assertion Authorization Grant.


--- middle

# Introduction

OAuth 2.0 deployments routinely pass credentials between system
components. A Client presents an assertion or subject token at the
Authorization Server's Token Endpoint to obtain an Access Token; a
Client then presents that Access Token at a Protected Resource to
invoke an operation. In each case the recipient may require specific
claims about the subject (an identifier, a directory attribute, or a
policy attribute), and the credential it receives may not carry
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

This specification separates the challenge (universal across
recipients and grants) from the Client's response (grant-specific).
It defines:

1. An OAuth 2.0 error code, `insufficient_claims`, returned by the
   recipient of a credential when that credential is otherwise
   acceptable but lacks claims required to fulfil the request. The
   error code is returned in Token Endpoint error responses
   ({{Section 5.2 of RFC6749}}) and in Bearer authentication
   challenges at Protected Resources ({{Section 3 of RFC6750}}).

2. A `required_claims` parameter that enumerates the missing claims
   using the same syntax as the `scope` parameter
   ({{Section 3.3 of RFC6749}}). The parameter is carried in the
   error response, in the authentication challenge, and (optionally)
   in OAuth 2.0 Protected Resource Metadata ({{RFC9728}}).

3. A `requested_claims` Token Endpoint request parameter that a
   Client includes on a back-channel re-issuance request to obtain a
   credential carrying the indicated claims. This parameter is
   defined for use with the OAuth 2.0 Token Exchange ({{RFC8693}})
   and Refresh Token ({{Section 6 of RFC6749}}) grants only. Other
   grants are addressed below.

4. A `required_claims` OAuth 2.0 Protected Resource Metadata
   ({{RFC9728}}) parameter by which a Protected Resource advertises
   the claims it may require, so Clients can request appropriate
   claims at Access Token issuance time and reduce the need for
   runtime challenges.

5. A `requested_claims_parameter_supported` OAuth 2.0 Authorization
   Server Metadata ({{RFC8414}}) parameter by which an Authorization
   Server advertises that it recognizes the `requested_claims`
   request parameter at its Token Endpoint.

The challenge applies to credentials presented at the Token Endpoint
under any grant, and to Access Tokens presented at Protected
Resources. The Client's response, however, is grant-specific:

* For OAuth 2.0 Token Exchange and Refresh Token grants, a Client
  responds to `insufficient_claims` by sending a back-channel
  Token Endpoint request that includes the `requested_claims`
  parameter defined in this document; see {{request-param}}.

* For grants that may require end-user interaction
  (authorization_code, device_code, CIBA, and similar), a Client
  responds by initiating a new authorization request, conveying its
  claim requirements via the OpenID Connect `claims` request
  parameter (Section 5.5 of {{OpenID.Core}}); see {{rel-oidc-claims}}.
  The `requested_claims` parameter defined here is not used with
  these grants.

The mechanism is opt-in and degrades gracefully. A recipient opts in
by returning `insufficient_claims`; a Client that does not recognize
the error treats the response as it would any other failure. An
Authorization Server that does not recognize the `requested_claims`
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

### Multi-Resource Refresh Tokens

A Client holding a Refresh Token that issues Access Tokens for
multiple audiences ({{Section 6 of RFC6749}}) may need different
claim sets in the Access Tokens it obtains for each audience. The
`requested_claims` parameter on the Refresh Token request lets the
Client request the audience-appropriate claim set for the next
Access Token without initiating a new authorization flow.

### Other Assertion-Based Grants

Any assertion-based grant defined by {{RFC7521}}, including JWT
Bearer ({{RFC7523}}) and SAML 2.0 Bearer ({{RFC7522}}), shares the
"incoming credential carrying claims" shape with Token Exchange.
This specification's error code applies uniformly to those grants;
how the Client obtains a richer assertion is governed by the
assertion provider's protocol and is out of scope for this document.


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
  Authorization Server the Client targets with `requested_claims`;
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

The `insufficient_claims` error code defined in {{error-code}}
applies to any OAuth 2.0 Token Endpoint request whose grant
presents a claim-bearing credential, including the OAuth 2.0 Token
Exchange grant ({{RFC8693}}), assertion-based grants ({{RFC7521}},
{{RFC7522}}, {{RFC7523}}), and the Refresh Token grant
({{Section 6 of RFC6749}}). The error code is decoupled from how a
Client responds: the `requested_claims` request parameter defined in
{{request-param}} is one response path, applicable to back-channel
re-issuance under Token Exchange and Refresh Token; for grants that
may require end-user interaction, the Client uses the OpenID Connect
`claims` request parameter (see {{rel-oidc-claims}}).

A Processing Authorization Server receiving a Token Endpoint request
MUST first validate the presented credential per its own acceptance
rules and the rules of the grant profile in use. If the credential
is rejected for cryptographic, audience, issuer, type, or freshness
reasons, the server MUST respond with the applicable error from
{{Section 5.2 of RFC6749}} (typically `invalid_grant`) rather than
the error defined here.

If the credential is acceptable but does not carry claims sufficient
to fulfil the request, the Processing Authorization Server MAY
respond with the error code defined in this section.

## Error Code {#error-code}

The error code is:

`insufficient_claims`:
: The credential presented in the Token Endpoint request is
  acceptable but does not carry claims sufficient for the Processing
  Authorization Server to fulfil the request.

The error code is returned in the `error` parameter of the Token
Endpoint error response, formatted per {{Section 5.2 of RFC6749}}
with HTTP status code 400.

## Response Parameter {#response-param}

The error response SHOULD include a `required_claims` parameter
enumerating the claims the Processing Authorization Server requires.

The `required_claims` value is a space-delimited list of claim
names. For example:

~~~
email given_name family_name
~~~

Each name identifies a claim as it appears in the credential (for
example, the JSON member name in a JWT). Claim names use the
`scope-token` syntax of {{Section 3.3 of RFC6749}}: visible ASCII
characters excluding space (`%x20`), double-quote (`%x22`), and
backslash (`%x5C`). Names are case-sensitive, and the order of names
in the list is not significant.

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

Claim names in `required_claims` are interpreted in the context of
the (issuer, subject, audience, Client) tuple of the request, in the
same way as the `scope` parameter ({{Section 3.3 of RFC6749}}); see
{{rel-scope}}. The Authorization Server's claim release policy, the
content and format of issued claims, and the meaning attached to a
given claim name are all scoped to that tuple. A value carried
verbatim from a `required_claims` field in an `insufficient_claims`
response into a `requested_claims` parameter on a retry Token
Endpoint request only retains its meaning when the audience, subject,
and Client are preserved, and the Issuing and Processing Authorization
Servers share an understanding of the claim names involved.

A Processing Authorization Server SHOULD NOT include the same claim
name more than once. A Client or Issuing Authorization Server
receiving duplicate claim names MUST treat the duplicates as a
single request for that claim.

## Token Endpoint Request Parameter for Back-Channel Re-Issuance {#request-param}

This document extends the Token Endpoint request ({{Section 3.2 of
RFC6749}}) with the following parameter:

`requested_claims`:
: OPTIONAL. A space-delimited list of claim names that the Client is
  requesting be included in the issued token. The syntax is
  identical to the `required_claims` error response parameter
  defined in this document. When included in a Token Endpoint
  request, the value is encoded as an
  `application/x-www-form-urlencoded` form parameter. The
  `requested_claims` parameter MUST NOT appear more than once in a
  single Token Endpoint request. A Client SHOULD NOT include the
  same claim name more than once within the value; an Authorization
  Server receiving duplicate claim names MUST treat them as a single
  request for that claim.

The `requested_claims` parameter is defined for use with the OAuth
2.0 Token Exchange grant ({{RFC8693}}) and the OAuth 2.0 Refresh
Token grant ({{Section 6 of RFC6749}}). These grants are back-channel
re-issuance flows in which the Client already holds a credential
that the Authorization Server can use to determine eligibility for
the requested claims, without a fresh end-user interaction. The
parameter MUST NOT be used with the `authorization_code` grant, the
`urn:openid:params:grant-type:ciba` grant, or other interactive
grants in which the Authorization Server may need to involve the
end user; see {{interactive-grants}} for guidance on those grants.

A Client MUST ensure that the `requested_claims` value it sends
conforms to the syntax defined in this document. If a value received
from a Processing Authorization Server in `required_claims` is
malformed, the Client MUST NOT forward it. A Client SHOULD forward
the value received in the `required_claims` field of the
`insufficient_claims` error response verbatim as the
`requested_claims` value, and MAY include additional claim names
based on local knowledge of the target resource.

### Use with Token Exchange

A Client retrying via Token Exchange sends a new Token Exchange
request to the Issuing Authorization Server. The Client selects the
`subject_token` and `subject_token_type` based on its established
credential relationship with the Issuing Authorization Server; this
is typically the same `subject_token` the Client originally exchanged
at that Authorization Server. The Client MUST set the `audience`
(and, if applicable, `resource`) parameters to identify the same
Processing Authorization Server or resource as the original request.

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
&requested_claims=email+given_name+family_name
~~~

### Use with Refresh Token

A Client holding a Refresh Token ({{Section 6 of RFC6749}}) MAY
include `requested_claims` on a Refresh Token request to obtain a
re-issued Access Token (and, where applicable, ID Token) carrying
the indicated claims. This is particularly useful for multi-resource
Refresh Tokens, where a single Refresh Token issues Access Tokens
for several audiences and the claim set required differs per
audience.

Example request:

~~~ http
POST /oauth2/token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=8xLOxBtZp8...
&audience=https%3A%2F%2Fapi.example.com%2F
&requested_claims=email+department
~~~

The Authorization Server applies its normal Refresh Token policy,
including any policy that would have applied had the Client
requested those claims at the original authorization. An
Authorization Server that would require fresh end-user consent to
release a requested claim MAY decline that claim or respond with an
error that prompts the Client to initiate a new authorization
request (see {{interactive-grants}}).

### Interactive Grants {#interactive-grants}

The `requested_claims` request parameter is not used with grants
that may require end-user interaction, including the
`authorization_code` grant, the `urn:ietf:params:oauth:grant-type:device_code`
grant, and the `urn:openid:params:grant-type:ciba` grant. For these
grants, a Client responding to `insufficient_claims` SHOULD initiate
a new authorization request and convey its claim requirements using
the OpenID Connect `claims` request parameter
(Section 5.5 of {{OpenID.Core}}); see {{rel-oidc-claims}}.

This separation lets the Authorization Server apply consent, user
authentication, or interaction policies appropriate to the new claim
release, rather than requiring those policies to be expressed as a
back-channel side effect.

## Authorization Server Metadata {#as-metadata}

An Authorization Server that supports the `requested_claims` request
parameter defined in {{request-param}} SHOULD advertise that support
in its OAuth 2.0 Authorization Server Metadata ({{RFC8414}}) using
the following metadata parameter:

`requested_claims_parameter_supported`:
: OPTIONAL. Boolean value indicating whether the Authorization Server
  supports the `requested_claims` Token Endpoint request parameter
  defined in this document. If omitted, the default value is `false`.

A Client MAY consult this metadata to determine whether to send
`requested_claims` on a Token Exchange or Refresh Token request,
including proactively on a first attempt where the Client expects
specific claims will be needed. A Client MUST NOT rely on the absence
or `false` value of this metadata to predict an Authorization
Server's behavior on `requested_claims`; an Authorization Server that
does not advertise support MAY still honor the parameter (consistent
with {{Section 3.2 of RFC6749}}).

This metadata parameter advertises support for the Token Endpoint
request parameter only. It does not advertise support for the
`insufficient_claims` error code in error responses; recipients
return that error code per their own policy regardless of metadata.

## Authorization Server Behavior

An Authorization Server that supports the `requested_claims` request
parameter on Token Exchange or Refresh Token requests SHOULD include
each requested claim in the issued token, subject to its own policy.
In particular, the Authorization Server:

* MUST NOT release a claim it would not otherwise release under its
  configured policy for the subject, the audience, and the
  requesting Client. Receipt of `requested_claims` is not
  authorization to bypass consent, privacy, or release controls.

* MUST NOT treat `requested_claims` as a complete enumeration of the
  claims that should be issued. The Authorization Server MAY include
  additional claims it would normally include.

* MAY decline to include any specific requested claim. Declining to
  include a claim is not, by itself, a reason to fail the request.

* SHOULD NOT fail the request because of an unrecognized claim name
  in `requested_claims`.

Issuance of a token in response to a `requested_claims` request is
not an assertion by the Authorization Server that all requested
claims were honored. A Client wishing to verify that a specific
claim is present in the re-issued token before retrying inspects the
issued token using the mechanisms applicable to its format.

## No Loop Guarantee {#no-loop}

This specification does not oblige the Issuing Authorization Server
to satisfy a `requested_claims` request, nor the Processing
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
Token depends on how the original Access Token was acquired:

* When the original Access Token was obtained via OAuth 2.0 Token
  Exchange ({{RFC8693}}), the Client SHOULD send a new Token
  Exchange request including the `requested_claims` parameter
  ({{request-param}}).

* When the original Access Token was obtained from a Refresh Token
  ({{Section 6 of RFC6749}}), the Client SHOULD send a Refresh Token
  request including the `requested_claims` parameter
  ({{request-param}}). This is particularly applicable to
  multi-resource Refresh Tokens.

* When the original Access Token was obtained via an interactive
  authorization flow (the `authorization_code` grant, the device
  authorization grant, the CIBA grant, or any other grant that may
  involve end-user interaction), the Client SHOULD initiate a new
  authorization request and convey its claim requirements using the
  OpenID Connect `claims` request parameter
  (Section 5.5 of {{OpenID.Core}}); see {{rel-oidc-claims}}. The
  `requested_claims` parameter defined in this document is not used
  in this case.

A Client SHOULD issue at most one retry per resource request in
response to `insufficient_claims`, and MUST treat any subsequent
`insufficient_claims` challenge for the same logical request as a
terminal failure to avoid retry loops.

## Protected Resource Metadata {#prm}

A Protected Resource MAY advertise the set of claims it may require
in its OAuth 2.0 Protected Resource Metadata document
({{RFC9728}}) using the following metadata parameter:

`required_claims`:
: OPTIONAL. A JSON array of strings, each value being a claim name in
  the syntax defined in {{response-param}}. The array enumerates
  claims the Protected Resource may require in Access Tokens.

Example metadata fragment:

~~~ json
{
  "resource": "https://api.example.com/",
  "authorization_servers": ["https://as.example.com/"],
  "scopes_supported": ["read", "write"],
  "required_claims": ["email", "given_name", "family_name"]
}
~~~

The advertised set is advisory and represents a maximal or typical
set of claims the resource may require across its operations. A
Client that obtains an Access Token carrying these claims SHOULD,
in the common case, avoid an `insufficient_claims` challenge.

The Protected Resource MAY still return `insufficient_claims` for
operations whose requirements depend on request path, parameters,
subject state, or policy, and is not obliged to require every
advertised claim for every operation. Clients SHOULD treat the
advertised list as a hint for Access Token acquisition and SHOULD
NOT depend on it as a complete or stable contract.

As with `required_claims` in error responses and challenges, and
`requested_claims` in Token Endpoint requests, claim names in the
metadata are interpreted in the context of the (issuer, subject,
audience, Client) tuple of any Access Token that will be presented
at the resource; see {{rel-scope}}.


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
   |  +requested_claims |                  |
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
   |  +requested_claims |                    |
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
using any of these grants. The `requested_claims` request parameter
({{request-param}}) is defined for Token Exchange and Refresh Token
grants and is not used with JWT Bearer or SAML Bearer requests
directly; the assertion presented in those grants is obtained out of
band, and obtaining a richer assertion is governed by the assertion
provider's protocol. Where the assertion provider is itself an
OAuth 2.0 Authorization Server, a Client receiving
`insufficient_claims` would typically obtain a richer assertion via
Token Exchange or via an interactive flow using the OpenID Connect
`claims` request parameter, and then present the new assertion in a
fresh JWT Bearer or SAML Bearer request.

## OAuth 2.0 `scope` Parameter {#rel-scope}

The `scope` parameter ({{Section 3.3 of RFC6749}}) is a coarse,
Authorization Server-specific authorization request signal. In some
deployment profiles, including OpenID Connect, specific scope values
(for example, `profile`, `email`) imply the issuance of specific
claims. This document does not redefine that mapping.

`required_claims` is finer-grained: a recipient names individual
claims directly, independent of any scope-to-claim mapping the
issuing Authorization Server may apply. The Client can forward a
precise requirement without knowing that mapping.

`required_claims` shares with `scope` the property that values are
interpreted in the context of the (issuer, subject, audience, Client)
tuple of the request. A claim name has no globally registered
semantics that override an Authorization Server's local release
policy; the same name may carry different content, format, or
release rules at different Authorization Servers, for different
subjects, audiences, or Clients. A Client forwarding claim names
between a recipient (in `required_claims`) and an Issuing Authorization
Server (in `requested_claims`) is relying on those two parties having
a shared understanding of the listed names,
typically through registered claims or profile alignment.

`required_claims` complements `scope` rather than replacing it. A
Client retrying at the Token Endpoint MAY include both parameters;
the Authorization Server applies its scope semantics as it otherwise
would, and additionally takes `required_claims` into account.

## OAuth 2.0 Resource Indicators (RFC 8707)

{{RFC8707}} allows a Client to specify the resource (the `resource`
parameter) at which the requested token will be used. The
Authorization Server may use that signal, together with the
`audience` parameter, to determine the audience of the issued token
and to apply audience-specific claim release policy. Two
consequences follow:

1. Claims releasable to one audience may not be releasable to
   another. A retry under {{request-param}} that changes the
   `audience` or `resource` value from the original request may
   obtain a token under different policy; the Authorization Server
   may include or omit different claims, and the recipient that
   returned `insufficient_claims` may not accept the re-issued
   token. For this reason {{request-param}} requires the Client to
   preserve the original `audience` and, where applicable,
   `resource` on retry.

2. A Processing Authorization Server or Protected Resource that
   returns `insufficient_claims` does so for a specific audience. A
   `required_claims` value that is meaningful for one audience may
   be meaningless, or trigger different release policy, for
   another.

## OpenID Connect `claims` Request Parameter {#rel-oidc-claims}

OpenID Connect Core 1.0 ({{OpenID.Core}}, Section 5.5) defines a
`claims` request parameter for use at the OIDC Authorization
Endpoint and Token Endpoint. The value is a JSON object that
requests individual claims for the ID Token and UserInfo responses,
with optional essential/voluntary semantics and value constraints.

This document defers to the OIDC `claims` parameter for any response
to `insufficient_claims` that requires a new authorization request,
including the `authorization_code` grant, the device authorization
grant, the CIBA grant, and similar interactive flows. In these
cases:

* The Client SHOULD initiate a new authorization request to the
  Authorization Server and include a `claims` parameter naming the
  claims that were enumerated in the `required_claims` field of the
  `insufficient_claims` response or challenge.

* The Authorization Server applies its normal interactive-flow
  policy: it MAY prompt the end user for consent, perform additional
  authentication, or otherwise involve the user before releasing
  newly requested claims. This is the natural place to handle such
  policy, which the back-channel `requested_claims` parameter
  ({{request-param}}) cannot accommodate.

* On completion of the new authorization request, the Client obtains
  an Access Token (and, where applicable, ID Token) carrying the
  requested claims, and retries the original request.

The `requested_claims` parameter defined in this document is not a
substitute for the OIDC `claims` parameter for interactive grants;
the two parameters target different stages of the OAuth 2.0 flow
and different deployment patterns:

* OIDC `claims` is presented at an Authorization or
  backchannel-authentication request, where end-user consent and
  authentication can be evaluated. It supports essential/voluntary
  claims and value constraints.

* `requested_claims` is presented at the Token Endpoint as part of
  a back-channel re-issuance request (Token Exchange or Refresh
  Token), where no end-user interaction occurs. It is a flat hint
  to the Authorization Server about which claims should be included
  in the issued token.

An Authorization Server MAY support both `claims` (on its OIDC
endpoints) and `requested_claims` (on its Token Endpoint Token
Exchange and Refresh Token requests); this document does not define
an interaction between them.

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
re-issued token in response to `requested_claims`, those claims may
be readable by the Client (for example, a JWT-formatted token can
be parsed by anyone holding the token). Authorization Servers SHOULD
apply the same release policy as for any other token issued to the
same subject, audience, and Client. Where the intended consumer is
the recipient only and the Client is treated as a transport,
security guidance from {{I-D.ietf-oauth-identity-assertion-authz-grant}}
on audience scoping and (where supported) encryption of the token
applies.

The Authorization Server is the policy authority for release.
Receipt of a `requested_claims` parameter from a Client MUST NOT be
treated as user consent, subject release authorization, or any other
form of override of the Authorization Server's configured policy. An
Authorization Server that finds that satisfying `requested_claims`
would violate policy MUST decline the affected claims and MAY
decline the request.

## Untrusted Input

A recipient constructing a `required_claims` field, and an
Authorization Server consuming a `requested_claims` parameter, MUST
treat the value as untrusted input until validated. Implementations
MUST validate that each token in the list conforms to the syntax
constraints stated in this document and MUST NOT pass the value into
log formatters, database queries, or claim release rules without
proper escaping or parameterization.

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
can add, remove, or modify the claim list it received in
`required_claims` before forwarding it as `requested_claims`. For
this reason `requested_claims` is advisory: the Issuing Authorization
Server SHOULD evaluate the request against the Client's identity,
the requested audience, and its local release policy. It MUST NOT
infer a recipient requirement from `requested_claims` alone, nor
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
specific entry in `requested_claims`.


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

IANA is requested to add the following entries to the "OAuth
Parameters" registry established by {{Section 11.2 of RFC6749}}.

### required_claims

Name:
: `required_claims`

Parameter Usage Location:
: token response, resource access authentication challenge

Change Controller:
: IETF

Specification Document(s):
: This document

### requested_claims

Name:
: `requested_claims`

Parameter Usage Location:
: token request

Change Controller:
: IETF

Specification Document(s):
: This document

## OAuth Protected Resource Metadata Registry

IANA is requested to add the following entry to the "OAuth Protected
Resource Metadata" registry established by {{Section 7.1 of RFC9728}}.

Metadata Name:
: `required_claims`

Metadata Description:
: A JSON array of claim names enumerating claims the Protected
  Resource may require in Access Tokens, advisory and not
  necessarily a complete or stable contract; see {{prm}}.

Change Controller:
: IETF

Specification Document(s):
: This document

## OAuth Authorization Server Metadata Registry

IANA is requested to add the following entry to the "OAuth
Authorization Server Metadata" registry established by
{{Section 7.1 of RFC8414}}.

Metadata Name:
: `requested_claims_parameter_supported`

Metadata Description:
: Boolean value indicating whether the Authorization Server supports
  the `requested_claims` Token Endpoint request parameter defined in
  this document; see {{as-metadata}}.

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
