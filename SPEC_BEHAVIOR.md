# RCAN version 2 behavior

## 1. Scope

This document specifies the observable authorization behavior of RCAN version
2: how capabilities are issued and delegated, how proof chains are evaluated,
and when an invocation is accepted or rejected.

The byte and text representations of delegations are specified separately in
`SPEC_SOL.md`.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be
interpreted as described in RFC 2119 and RFC 8174.

## 2. Model

An RCAN identity is an Ed25519 public key. Possession of its corresponding
signing key represents control of that identity.

An authorizer is configured with one identity, called the **capability owner**.
The authorizer decides whether an authenticated invoker may exercise a requested
capability owned by that identity.

A delegation contains:

- an `issuer`, which signed the delegation;
- an `audience`, which receives it;
- a `capability_owner`;
- an expiry condition; and
- a granted capability.

The wire format represents `capability_owner` indirectly:

```text
capability_owner(d) = d.issuer       if d.origin is Issuer
                    = d.origin.key   if d.origin is Delegation(key)
```

Every delegation accepted by the decoding API has already passed structural,
canonicality, and signature verification. Invocation checking relies on that
invariant and does not verify the signature again.

## 3. Capabilities

Capability meaning is defined by the application. A capability type supplies a
predicate:

```text
permits(grant, request) -> boolean
```

`permits(grant, request)` is true exactly when `grant` authorizes `request`.
RCAN imposes no hierarchy, reflexivity, transitivity, or other algebraic laws
on this predicate. Applications are responsible for implementing the desired
policy.

For example, an application might define:

```text
All       permits All, ReadWrite, and Read
ReadWrite permits ReadWrite and Read
Read      permits Read only
```

## 4. Creating delegations

### 4.1 Issuing an owned capability

An owner issues a capability by constructing a delegation with:

```text
issuer           = owner's public key
audience         = recipient's public key
capability_owner = issuer
capability       = application-supplied grant
expiry           = application-supplied expiry
```

The delegation is signed by the issuer.

### 4.2 Passing on another identity's capability

A holder passes on a capability by constructing a delegation with:

```text
issuer           = holder's public key
audience         = next recipient's public key
capability_owner = original owner's public key
capability       = application-supplied grant
expiry           = application-supplied expiry
```

The delegation is signed by the holder.

The construction API does not require proof that the issuer currently holds
the stated capability, does not compare the new grant with an earlier grant,
and does not constrain the new expiry. Such a delegation has authority only
when it appears in a proof chain for which all checks in section 6 succeed.

## 5. Invocations and authentication

An authorization decision has these inputs:

```text
owner       the authorizer's identity
invoker     the authenticated caller's identity
request     the requested capability
proofs      an ordered sequence of delegations
now         the evaluation time
```

The caller's identity MUST be authenticated outside RCAN, and the application
MUST ensure that the authenticated caller signed or otherwise authenticated the
message containing `request`. Supplying an `invoker` public key to the check is
not itself authentication, and RCAN does not sign invocation messages.

## 6. Proof-chain evaluation

Proofs are ordered from the owner toward the invoker, sometimes described as
root-to-leaf or back-to-front:

```text
owner --proof[0]--> holder 1 --proof[1]--> ... --proof[n-1]--> invoker
```

Authorization is equivalent to the following algorithm:

```text
expected_issuer = owner

for proof in proofs:
    if proof.issuer != expected_issuer:
        reject ChainBroken(expected_issuer, proof.issuer)

    if proof.expiry is At(t) and now > t:
        reject Expired(proof.expiry)

    if capability_owner(proof) != owner:
        reject WrongCapabilityIssuer(owner)

    if proof.capability cannot be decoded completely as the request's type:
        reject NotPermitted

    if not permits(proof.capability, request):
        reject NotPermitted

    expected_issuer = proof.audience

if invoker != expected_issuer:
    reject WrongInvoker(invoker, expected_issuer)

accept
```

Checks occur in the order shown. Evaluation stops at the first failure, so the
reported error is order-dependent.

### 6.1 Chain continuity

The first proof MUST be issued by the owner. Every later proof MUST be issued by
the audience of the immediately preceding proof. The final proof's audience
MUST equal the authenticated invoker.

The chain does not contain a separate link identifier. Public-key equality
establishes continuity.

### 6.2 Capability ownership

Every proof, not only the first one, MUST name the authorizer's identity as its
capability owner. Consequently, a proof chain cannot combine grants rooted in
different owners.

An `Issuer` origin is suitable for the first proof because its issuer is the
owner. A later proof normally uses `Delegation(owner)`. The rule is expressed
only in terms of the derived `capability_owner`, however; there is no separate
requirement on which origin variant occurs at a particular position.

### 6.3 Capability attenuation

Every grant in the chain is independently tested against the same requested
capability:

```text
permits(proof[i].capability, request) == true  for every i
```

Adjacent grants are not compared with each other. In particular, RCAN does not
evaluate:

```text
permits(proof[i].capability, proof[i + 1].capability)
```

This still prevents a request from exceeding any grant in the presented chain:
the effective authority of the chain is the intersection of all grants, as
observed through `permits`. It does mean that the validity of an intermediate
delegation is determined only in the context of the eventual request.

### 6.4 Expiry

`Never` is valid at every supported evaluation time. `At(t)` is inclusive: it
is valid at second `t` and invalid beginning at `t + 1`.

Every proof's expiry is checked independently. The chain is valid only while
all its links are valid. A later `Never` expiry does not extend an earlier
finite expiry, and a later timestamp after an earlier timestamp does not extend
the chain beyond the earlier timestamp.

The default checking operation evaluates at the system's current time. The
explicit-time operation uses its supplied time. The reference implementation
expects evaluation times at or after the Unix epoch; supplying an earlier time
causes a panic rather than an authorization error.

### 6.5 Empty proof chains

For an empty proof sequence, no expiry or capability predicate is evaluated.
The invocation is accepted exactly when `invoker == owner`.

Thus, the capability owner needs no delegation to invoke any of its own
capabilities. If the invoker differs from the owner, the result is
`WrongInvoker`.

## 7. Typed and opaque proofs

Decoding or converting an opaque delegation into a typed delegation requires
its capability bytes to decode completely as the chosen capability type. A
decoding failure or trailing capability bytes cause that operation to fail.

The local builder serializes the supplied capability into a typed delegation;
it does not deserialize the bytes again. A capability type whose serialization
does not round-trip can therefore be constructed locally but will be treated as
`NotPermitted` during invocation checking.

An opaque delegation retains capability bytes without assigning them an
application type. When an opaque proof chain is checked, each proof's bytes are
decoded as the requested capability type during evaluation. Failure to decode
the complete byte string is treated as `NotPermitted`, not as a malformed proof
chain.

Invocation checking decodes the stored capability bytes even for typed proofs.
Subject to successful capability decoding, typed and opaque proof chains use
the same authorization algorithm and produce the same decision.

## 8. Failure conditions

Invocation checking exposes these semantic failures:

| Failure | Condition |
| --- | --- |
| `ChainBroken` | A proof's issuer differs from the owner or preceding audience expected at that position. |
| `Expired` | The current time is later than that proof's finite expiry. |
| `WrongCapabilityIssuer` | A proof's derived capability owner differs from the authorizer. |
| `NotPermitted` | A capability cannot be decoded as required, has trailing bytes, or its `permits` predicate rejects the request. |
| `WrongInvoker` | The authenticated invoker differs from the last audience, or from the owner for an empty chain. |

Malformed encodings and invalid signatures are decoding failures and therefore
occur before invocation checking.

## 9. Worked example

Let `S` be a service and capability owner, `A` an intermediate holder, and `B`
the authenticated invoker:

```text
d0 = S -> A, owner S, grant All,  expires At(4102444800)
d1 = A -> B, owner S, grant Read, expires Never
proofs = [d0, d1]
```

At a time not later than `4102444800`:

- a `Read` request by `B` succeeds if both `All.permits(Read)` and
  `Read.permits(Read)` are true;
- a `ReadWrite` request fails if `Read.permits(ReadWrite)` is false;
- the same `Read` request authenticated as some identity other than `B` fails
  with `WrongInvoker`;
- reversing the proofs fails chain continuity; and
- evaluating after `4102444800` fails because `d0` has expired, despite `d1`
  never expiring.

## 10. Security responsibilities

RCAN proves that a sequence of authenticated delegation statements connects an
owner to an invoker and that every statement permits a requested capability.
It does not by itself:

- authenticate the transport or caller;
- bind an invocation message to the `invoker` key;
- define capability meaning or a safe `permits` relation;
- prevent a key holder from signing useless or over-broad delegations;
- select, discover, or reorder proofs; or
- provide revocation other than expiry and application-level policy.

Applications MUST supply those surrounding controls where required.

## 11. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
