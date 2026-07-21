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

// view (no deploy): used by on-chain validators
SignatureValidator.isValidSignatureNow(signer, hash, signature);

// non-view (deploys a counterfactual ERC-6492 account first):
SignatureValidator.isValidSignatureNowWithSideEffects(signer, hash, signature);
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

**ECDSA signature length.** The ECDSA leg uses OZ `ECDSA.tryRecover(bytes32,bytes)`, which accepts
only 65-byte `(r,s,v)` signatures across the entire supported OZ 5.x range (EIP-2098 64-byte
compact signatures use OZ's separate `(r,vs)` overload, which this library does not call).
Behavior is therefore consistent across OZ 5.x — the ECDSA leg is deterministic regardless of the
consumer's 5.x minor version. OZ marks that overload's 65-byte-only restriction as deprecated and
slated for removal in v6.0 — i.e. in v6.0 `tryRecover(bytes32,bytes)` will begin accepting 64-byte
EIP-2098 compact signatures. To keep the deterministic 65-byte-only behavior this library relies on,
it pins OZ `<6.0.0`.

**EVM version.** Compiled/tested at `evm_version = cancun` (uses PUSH0). Since the library is
inlined, the consumer's compiler settings govern deployment — consumers targeting pre-PUSH0 /
older chains should set their own `evm_version` accordingly (EIP-7702's audience is multi-chain).

## Security notes

**EIP-7702 root-key override.** For a 7702 signer, a valid signature from the account's root
EOA key over `hash` is accepted **unconditionally** via the ECDSA leg, overriding any restriction
the account's own delegate `isValidSignature` would otherwise enforce (e.g. wrapped-digest replay
protection, session-key scoping, 2FA). Consumers that rely on a 7702 account's own signature
policy must account for this before adopting the dual-path check.

**`isValidSignatureNowWithSideEffects` is an arbitrary-call surface.** This function makes an
external call `factory.call(factoryCalldata)` where both the target and calldata come straight
from the (untrusted) signature, executed from the caller's own context, whenever `signer` has no
code and `factory` is non-zero — before and independent of whether the signature ultimately
validates. Treat it as an arbitrary-call / reentrancy primitive.

> **Precondition (not advisory).** A consumer that calls `isValidSignatureNowWithSideEffects` **MUST**
> gate it behind a reentrancy guard and **MUST NOT** hold funds, token approvals, or privileged roles
> at the call site. Adopting it without both is a security defect in the consumer. Only pass signatures
> from a trusted source. Prefer the view-only `isValidSignatureNow` unless counterfactual account
> deployment is specifically required — the Krystal vault automators use only the view entry.

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
