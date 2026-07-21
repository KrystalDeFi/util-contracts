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
