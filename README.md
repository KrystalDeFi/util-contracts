# util-contracts

Krystal utility smart contracts.

## SignatureValidator

Dual-path signature validation: a signature is valid if **either** an ERC-1271
check **or** an ECDSA recovery succeeds. Unlike OZ/Solady `SignatureChecker`
(which picks one path by `signer.code.length`), this attempts both — required
for EIP-7702 accounts that have code *and* a key. Supports ERC-6492 wrapped
signatures for counterfactual accounts.

```solidity
import { SignatureValidator } from "@krystal/util-contracts/contracts/SignatureValidator.sol";

// view (no deploy, no external CALL): used by on-chain validators. Safe with untrusted input.
SignatureValidator.isValidSignatureNow(signer, hash, signature);

// non-view (deploys a counterfactual ERC-6492 account first). The deploy is isolated in a stateless
// singleton — deploy ONE per chain and pass its address as `validator`:
//   SignatureValidatorSingleton validator = new SignatureValidatorSingleton(); // once per chain
SignatureValidator.isValidSignatureNowWithSideEffects(address(validator), signer, hash, signature);
```

### Install (consumers)

```
yarn add github:KrystalDeFi/util-contracts
```

Add to `remappings.txt`:
```
@krystal/util-contracts/=node_modules/@krystal/util-contracts/
```

### Develop

```
npm install && forge test -vvv
```

## Compatibility

**ECDSA signature formats.** The ECDSA leg accepts both 65-byte `(r,s,v)` and 64-byte EIP-2098
compact `(r,vs)` signatures. A 64-byte input is routed through OZ `ECDSA.tryRecover(bytes32,bytes32,bytes32)`
(the `(r,vs)` overload); anything else through `ECDSA.tryRecover(bytes32,bytes)`. Both overloads
enforce low-s malleability rejection and signal errors via a `RecoverError` return rather than
reverting. (On malleability of the compact form: the `vs` field only encodes `s < 2^255`, which alone
blocks the high-s window `[2^255, N)`; the remaining malleable values `s ∈ (N/2, 2^255)` *are*
encodable but are rejected by OZ's low-s guard — see `test_ecdsa_64byteCompactSig_highS_rejected`,
which exercises `s = N/2 + 1`.) The library targets the OZ 5.x `ECDSA` API — the
`tryRecover` overloads and the `RecoverError` 3-tuple return — and pins `<6.0.0` for API stability
across that audited line.

**EVM version.** Compiled/tested at `evm_version = cancun` (uses PUSH0). Since the library is
inlined, the consumer's compiler settings govern deployment — consumers targeting pre-PUSH0 /
older chains should set their own `evm_version` accordingly (EIP-7702's audience is multi-chain).

## Security notes

**EIP-7702 root-key override.** For a 7702 signer, a valid signature from the account's root
EOA key over `hash` is accepted **unconditionally** via the ECDSA leg, overriding any restriction
the account's own delegate `isValidSignature` would otherwise enforce (e.g. wrapped-digest replay
protection, session-key scoping, 2FA). Consumers that rely on a 7702 account's own signature
policy must account for this before adopting the dual-path check.

**`isValidSignatureNowWithSideEffects` deploys via an isolated singleton.** The ERC-6492 factory
call (`factory.call(factoryCalldata)`, target + calldata from the untrusted signature) is executed
inside the `validator` singleton's context — the callee sees `msg.sender == the singleton`, a
stateless, privilege-less contract that holds no funds, approvals, or roles. This is the ERC-6492
reference `UniversalSigValidator` isolation model, and it removes the *drain* vector an inlined
deploy would expose (`factory = token; calldata = transfer(attacker, …)` can only act as the empty
singleton — there is nothing to take).

> **Precondition (not advisory).** Two obligations remain for `isValidSignatureNowWithSideEffects`:
> **(1)** `validator` **MUST** be a deployed, trusted `SignatureValidatorSingleton` that is kept
> stateless and privilege-less — never grant it roles/approvals or let it hold a balance (that empties
> the isolation). **(2)** The attacker-controlled factory call (running as the singleton) can still
> **re-enter the consumer**, so a consumer that calls this while holding funds/roles **MUST** gate the
> call behind a reentrancy guard. Singleton isolation defeats the single-call *drain*; it does not by
> itself defeat *re-entry*. Prefer the view-only `isValidSignatureNow` (no CALL at all) for
> fully-untrusted input. The Krystal vault automators use only the view entry, so this surface is not
> reachable in the shipped product.

**ERC-1271 return data is bounded, and never reverts.** The ERC-1271 leg copies at most the first
32-byte word of the signer's return data (via a bounded `staticcall`), so a malicious signer cannot
force an unbounded return-data copy into the caller's memory to grief the validation. It compares that
word in full against the magic value (as OZ's `SignatureChecker` does); a non-compliant wallet whose
return word has the magic in its top bytes but dirty low-order bytes — e.g. one returning `bool true`
— yields `false` rather than reverting inside `abi.decode` (which enforces strict ABI padding),
upholding the never-reverts guarantee. The verdict is unchanged for any well-formed wallet.

**ERC-6492 detection is heuristic.** A signature is treated as 6492-wrapped when it is at least 128
bytes and its last 32 bytes equal the magic suffix. A genuine (non-6492) signature that happens to be
≥128 bytes and end in that suffix would be misparsed as a wrapper — this is inherent to ERC-6492's
detection scheme, not specific to this library. The unwrap is bounds-checked and never reverts, so a
misparse degrades to a normal (invalid) result rather than an error.

**Signature encodings are not unique.** Because the ECDSA leg accepts both 65-byte `(r,s,v)` and
64-byte EIP-2098 `(r,vs)` forms, a single authorization has two on-chain encodings that recover to the
same signer and are freely inter-convertible **without** the signing key (drop `v`, fold its parity
into `s`'s top bit, and back). Therefore `keccak256(signature)` is **not** a stable unique identifier:
a consumer that does replay protection by tracking used signature bytes (e.g. `mapping(bytes32 => bool)`
keyed on the signature hash) is bypassable — an observer resubmits the other encoding of the same
authorization for a distinct key. Do replay protection via **nonces or hash/digest invalidation**,
never by tracking signature bytes. (OZ's own `ECDSA` NatSpec makes the same warning.) The Krystal vault
automators are unaffected: they key cancellation/replay on the EIP-712 **digest**, not the signature.
