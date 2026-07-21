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

**ECDSA signature length.** The ECDSA leg delegates to OpenZeppelin `ECDSA.tryRecover`. On OZ
**≥5.6** it accepts only 65-byte `(r,s,v)` signatures (EIP-2098 64-byte compact are rejected); on
5.0–5.5 both are accepted. This library is validated against OZ ≥5.6. Because the library is
distributed as source and inlined into the consumer's build, the **consumer's** resolved OZ
version governs — pin OZ ≥5.6 for deterministic 65-byte-only behavior.

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
validates. Treat it as an arbitrary-call / reentrancy primitive: gate it behind a reentrancy guard,
never invoke it mid-operation while holding funds, approvals, or privileged roles, and only pass
signatures from a trusted source. Prefer the view-only `isValidSignatureNow` unless counterfactual
account deployment is specifically required.
