# SignatureValidator Version-Agnostic (inline ECDSA) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `@krystal/util-contracts`'s `SignatureValidator` compile unmodified under both v3utils (solc 0.8.15 / OZ 4.9.6) and v4utils (solc 0.8.26 / OZ 5.3.0) by inlining ECDSA recovery and removing the OZ `ECDSA` dependency, without changing behavior.

**Architecture:** `SignatureValidator` already hand-rolls all signature parsing in assembly and delegates only the final recovery tail to OpenZeppelin's `ECDSA.tryRecover`. That tail is the sole source of the OZ-version coupling (2-value return in OZ 4.9 vs 3-value in OZ 5.x). We replace it with a private `_recover` that inlines OZ's exact logic (low-`s` malleability rejection + `ecrecover` + zero-address check), drop the `ECDSA` import (keep `IERC1271`, which is stable across OZ versions), and lower the pragma to `^0.8.0`.

**Tech Stack:** Solidity, Foundry (`forge`), OpenZeppelin Contracts (only `IERC1271` after this change), forge-std.

## Global Constraints

- **Pragma floor:** source pragmas become `^0.8.0` (must compile on solc 0.8.15 through 0.8.28). Only language features ≥0.8.13-safe may be used; `assembly ("memory-safe")` is allowed (introduced 0.8.13, already used in this file and compiled on 0.8.15 by v3utils).
- **No new dependencies:** the only permitted OZ import in `contracts/` is `@openzeppelin/contracts/interfaces/IERC1271.sol`. No Solady, no `ECDSA`.
- **Behavior preserved exactly:** the accept set must not change. Low-`s` (upper-half) signatures stay **rejected**; `ecrecover` returning `address(0)` stays a failure; only 65-byte `(r,s,v)` and 64-byte EIP-2098 `(r,vs)` inputs are accepted.
- **Malleability constant (verbatim from OZ):** `0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` (= secp256k1n ÷ 2).
- **Never-reverts contract:** `isValidSignatureNow` / `isValidSignatureNowWithSideEffects` must never revert on untrusted input.
- **Formatting:** 2-space indent, double quotes, `bracket_spacing = true`, `line_length = 120` (per `foundry.toml [fmt]`). Run `forge fmt` before committing.
- **Test toolchain keeps OZ:** the test file continues to import OZ `ECDSA`/`SignatureChecker` as the differential oracle — util-contracts' own dev env has OZ 5.6.1. Only `contracts/` drops the `ECDSA` dependency.

---

### Task 0: Environment setup (prerequisite)

**Files:** none (dependency install only)

- [ ] **Step 1: Initialize forge-std submodule and install OZ**

```bash
cd ~/projects/util-contracts
git submodule update --init --recursive
npm install --no-audit --no-fund
```

- [ ] **Step 2: Confirm the baseline suite is green (35 tests)**

Run: `forge test`
Expected: `35 tests passed, 0 failed, 0 skipped` (2 suites). This is the safety net for the refactor.

---

### Task 1: Add differential + legacy-`v` characterization tests

Add tests that pin the ECDSA leg to OZ's semantics. They must pass against the **current** OZ-based implementation (establishing the oracle baseline); Task 2 must keep them green after the inline swap.

**Files:**
- Modify: `test/SignatureValidator.t.sol` (add three test functions to `contract SignatureValidatorTest`, before its closing `}` at line 382)

**Interfaces:**
- Consumes: `SignatureValidator.isValidSignatureNow(address,bytes32,bytes) returns (bool)`; `ECDSA.tryRecover(bytes32,bytes) returns (address, ECDSA.RecoverError, bytes32)` (OZ 5.x oracle); forge-std `vm.sign`, `vm.addr`, `bound`.
- Produces: nothing consumed by later tasks (tests only).

- [ ] **Step 1: Add the three test functions**

Insert immediately before the closing brace of `contract SignatureValidatorTest` (currently line 382, after `test_ecdsa_oddLengthSig_rejected`):

```solidity
  // Differential fuzz: the ECDSA leg must agree with OpenZeppelin's ECDSA.tryRecover for every
  // well-formed signature, in both 65-byte (r,s,v) and 64-byte EIP-2098 (r,vs) encodings. vm.sign
  // yields a canonical (low-s, v in {27,28}) signature, so OZ validates it and so must we.
  function testFuzz_ecdsa_matchesOZ(uint256 pkSeed, bytes32 hash) public view {
    // secp256k1 order N; bound the key to [1, N-1] so vm.sign gets a valid private key.
    uint256 pk = bound(pkSeed, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
    address signer = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);

    bytes memory sig65 = abi.encodePacked(r, s, v);
    (address ozRec, ECDSA.RecoverError ozErr,) = ECDSA.tryRecover(hash, sig65);
    bool ozValid = ozErr == ECDSA.RecoverError.NoError && ozRec == signer;
    assertTrue(ozValid); // canonical signature: OZ always accepts
    assertEq(SignatureValidator.isValidSignatureNow(signer, hash, sig65), ozValid);

    // Same signature re-encoded as EIP-2098 compact form must match too.
    bytes32 vs = bytes32((uint256(v - 27) << 255) | uint256(s));
    assertEq(SignatureValidator.isValidSignatureNow(signer, hash, abi.encodePacked(r, vs)), ozValid);
  }

  // Differential fuzz across the malleability boundary: the malleated (high-s, flipped-v) form of any
  // valid signature must be rejected by BOTH the library and OZ, proving the low-s guard matches OZ.
  function testFuzz_ecdsa_malleated_matchesOZ(uint256 pkSeed, bytes32 hash) public view {
    uint256 pk = bound(pkSeed, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
    address signer = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);

    uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // secp256k1 order N
    bytes memory malleated = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    (address ozRec, ECDSA.RecoverError ozErr,) = ECDSA.tryRecover(hash, malleated);
    bool ozValid = ozErr == ECDSA.RecoverError.NoError && ozRec == signer;
    assertFalse(ozValid); // OZ rejects upper-half s
    assertEq(SignatureValidator.isValidSignatureNow(signer, hash, malleated), ozValid);
  }

  // Raw legacy v in {0,1} (not 27/28) must be rejected: ecrecover yields address(0) for such v. Both OZ
  // and the inline leg rely on that address(0) result, so neither validates the signature.
  function test_ecdsa_rawLegacyV_rejected() public view {
    uint256 pk = 0xA11CE;
    address eoa = vm.addr(pk);
    (, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, abi.encodePacked(r, s, uint8(0))));
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, abi.encodePacked(r, s, uint8(1))));
  }
```

- [ ] **Step 2: Run the new tests — they must PASS against the current OZ impl**

Run: `forge test --match-test "testFuzz_ecdsa_matchesOZ|testFuzz_ecdsa_malleated_matchesOZ|test_ecdsa_rawLegacyV_rejected" -v`
Expected: 3 tests PASS (fuzz tests run 256 runs each). This proves the new tests correctly characterize OZ's behavior.

- [ ] **Step 3: Run the full suite (regression)**

Run: `forge test`
Expected: `38 tests passed, 0 failed` (35 baseline + 3 new).

- [ ] **Step 4: Format and commit**

```bash
forge fmt
git checkout -b inline-ecdsa-version-agnostic
git add test/SignatureValidator.t.sol
git commit -m "test(SignatureValidator): add differential-vs-OZ and legacy-v ECDSA tests"
```

---

### Task 2: Inline ECDSA recovery in `SignatureValidator.sol`

Replace the OZ `ECDSA.tryRecover` tail with a private `_recover`, drop the `ECDSA` import, and lower the pragma. The full suite (including Task 1's differential tests) is the pass/fail gate — behavior must be identical.

**Files:**
- Modify: `contracts/SignatureValidator.sol` (line 2 pragma; line 4 import; lines 96–111 in `_dualCheck`; add `_HALF_CURVE_ORDER` constant and `_recover` helper)

**Interfaces:**
- Consumes: global `ecrecover(bytes32,uint8,bytes32,bytes32) returns (address)`; `IERC1271` (unchanged).
- Produces: `function _recover(bytes32 hash, bytes memory sig) private pure returns (address)` — returns the recovered signer, or `address(0)` on any failure (bad length, upper-half `s`, invalid `v`/signature). Never reverts. Used only inside `_dualCheck`.

- [ ] **Step 1: Change the pragma (line 2)**

Replace:

```solidity
pragma solidity ^0.8.20;
```

with:

```solidity
pragma solidity ^0.8.0;
```

- [ ] **Step 2: Remove the OZ ECDSA import (line 4)**

Delete this line entirely (keep the `IERC1271` import on line 5):

```solidity
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
```

- [ ] **Step 3: Replace the ECDSA leg comment + body in `_dualCheck` (lines 93–111)**

Replace the whole Leg-2 block — the 4-line comment starting `// Leg 2: ECDSA — attempted EVEN...` (line 93) through `return err == ECDSA.RecoverError.NoError && recovered == signer;` (line 111) — with this single contiguous block (do not leave the old comment behind):

```solidity
    // Leg 2: ECDSA — attempted EVEN when the signer has code (the EIP-7702 case). Delegates to _recover
    // (inlined ECDSA, matching OpenZeppelin ECDSA.tryRecover): accepts a 65-byte (r,s,v) signature and a
    // 64-byte EIP-2098 compact (r,vs) signature, enforces low-s malleability rejection, and never reverts
    // (any invalid input recovers address(0)).
    address recovered = _recover(hash, sig);
    // `signer` is guaranteed non-zero by isValidSignatureNow's entry guard, so a zero `recovered` (the
    // failure sentinel) can never spuriously match; the explicit check keeps the intent local.
    return recovered != address(0) && recovered == signer;
```

- [ ] **Step 4: Add the constant and `_recover` helper**

Insert immediately after `_dualCheck`'s closing brace (before the `_isValidERC1271` NatSpec block, ~line 113), the following:

```solidity
  /// @dev secp256k1n ÷ 2 — the upper bound of the canonical (low-s) range. Copied verbatim from
  ///      OpenZeppelin's ECDSA to preserve identical malleability rejection.
  uint256 private constant _HALF_CURVE_ORDER =
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

  /// @dev Inlined ECDSA recovery matching OpenZeppelin `ECDSA.tryRecover`, so the library no longer
  ///      depends on OZ's `ECDSA` (whose `tryRecover` return arity differs between OZ 4.9 and 5.x and
  ///      is the sole obstacle to compiling under both toolchains). Accepts only a 65-byte `(r,s,v)`
  ///      signature or a 64-byte EIP-2098 `(r,vs)` compact signature; rejects an upper-half `s`
  ///      (malleability) and treats a zero `ecrecover` result (invalid `v`/signature) as failure. Returns
  ///      `address(0)` on any failure and NEVER reverts — preserving the library's never-reverts contract.
  function _recover(bytes32 hash, bytes memory sig) private pure returns (address) {
    bytes32 r;
    bytes32 s;
    uint8 v;
    if (sig.length == 65) {
      assembly ("memory-safe") {
        r := mload(add(sig, 0x20))
        s := mload(add(sig, 0x40))
        v := byte(0, mload(add(sig, 0x60)))
      }
    } else if (sig.length == 64) {
      bytes32 vs;
      assembly ("memory-safe") {
        // A 64-byte `bytes memory` holds exactly r || vs in its data region [sig+0x20, sig+0x60).
        r := mload(add(sig, 0x20))
        vs := mload(add(sig, 0x40))
      }
      // EIP-2098: `s` is `vs` with the top bit cleared; `v` is 27 + that top (yParity) bit.
      s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
      v = uint8((uint256(vs) >> 255) + 27);
    } else {
      return address(0); // any other length is not a supported ECDSA encoding
    }
    // Reject upper-half `s` (signature malleability), matching OZ's low-s guard.
    if (uint256(s) > _HALF_CURVE_ORDER) return address(0);
    // `ecrecover` returns address(0) for an invalid `v` (not 27/28) or an unrecoverable signature.
    return ecrecover(hash, v, r, s);
  }
```

- [ ] **Step 5: Verify the ECDSA import is gone and no `ECDSA.` references remain in `contracts/`**

Run: `grep -rn "ECDSA" contracts/`
Expected: no output (zero matches).

- [ ] **Step 6: Run the full suite — must stay green**

Run: `forge test`
Expected: `38 tests passed, 0 failed`. In particular `testFuzz_ecdsa_matchesOZ`, `testFuzz_ecdsa_malleated_matchesOZ`, `test_ecdsa_highSMalleable_rejected`, `test_ecdsa_64byteCompactSig_accepted`, and `test_ecdsa_rawLegacyV_rejected` all PASS — proving the inline `_recover` matches OZ exactly.

- [ ] **Step 7: Confirm it compiles on the v3utils floor (solc 0.8.15)**

Run: `forge build --use 0.8.15 --skip test`
Expected: compiles successfully (Foundry auto-downloads solc 0.8.15). This proves the pragma and language features satisfy the lowest target toolchain. (The `test/` files pin `^0.8.20`; `--skip test` excludes them.)

- [ ] **Step 8: Format and commit**

```bash
forge fmt
git add contracts/SignatureValidator.sol
git commit -m "refactor(SignatureValidator)!: inline ECDSA recovery, drop OZ ECDSA dependency

Replaces OZ ECDSA.tryRecover (whose 2-vs-3 return arity across OZ 4.9/5.x
blocked compiling under both v3utils and v4utils) with an in-library _recover
that preserves identical behavior: low-s malleability rejection, address(0)
on failure, 65-byte and EIP-2098 64-byte support. Pragma lowered to ^0.8.0.
Only IERC1271 remains imported from OZ."
```

---

### Task 3: Singleton pragma + package metadata

**Files:**
- Modify: `contracts/SignatureValidatorSingleton.sol:2` (pragma)
- Modify: `package.json` (OZ dependency range)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Lower the singleton pragma**

In `contracts/SignatureValidatorSingleton.sol`, replace line 2:

```solidity
pragma solidity ^0.8.20;
```

with:

```solidity
pragma solidity ^0.8.0;
```

- [ ] **Step 2: Relax the OZ dependency range**

In `package.json`, change the dependency (only `IERC1271` is used now, present since OZ 4.x):

```json
  "dependencies": {
    "@openzeppelin/contracts": ">=4.9.0 <6.0.0"
  }
```

- [ ] **Step 3: Full suite still green**

Run: `forge test`
Expected: `38 tests passed, 0 failed`.

- [ ] **Step 4: Singleton compiles on the 0.8.15 floor too**

Run: `forge build --use 0.8.15 --skip test`
Expected: compiles successfully (both `contracts/` files).

- [ ] **Step 5: Commit**

```bash
git add contracts/SignatureValidatorSingleton.sol package.json
git commit -m "chore(SignatureValidator): lower singleton pragma to ^0.8.0; relax OZ range to >=4.9.0"
```

---

### Task 4: Tri-toolchain verification (prove it fits both consumers)

Prove the modified upstream compiles under each consumer's real toolchain by test-dropping the file into each repo and building — **without** yet committing any permanent wiring (that's Task 5). Use a scratch copy so the repos stay clean.

**Files:**
- No repo files changed. Temporary drop-in build only; revert after.

**Interfaces:**
- Consumes: the modified `~/projects/util-contracts/contracts/SignatureValidator.sol` from Task 2.

- [ ] **Step 1: Verify v4utils (solc 0.8.26 / OZ 5.3.0) still builds**

v4utils consumes upstream via its `lib/util-contracts` submodule. Point that submodule checkout at the working copy and build:

```bash
cd ~/projects/v4utils
git submodule update --init lib/util-contracts 2>/dev/null || true
cp ~/projects/util-contracts/contracts/SignatureValidator.sol lib/util-contracts/contracts/SignatureValidator.sol
cp ~/projects/util-contracts/contracts/SignatureValidatorSingleton.sol lib/util-contracts/contracts/SignatureValidatorSingleton.sol
forge build 2>&1 | tail -5
```

Expected: `Compiler run successful` (or no errors) under solc 0.8.26 / OZ 5.3.0.

- [ ] **Step 2: Restore v4utils's submodule file**

```bash
cd ~/projects/v4utils && git -C lib/util-contracts checkout -- contracts/ 2>/dev/null || true
```

- [ ] **Step 3: Verify v3utils (solc 0.8.15 / OZ 4.9.6) builds the upstream file**

v3utils's vendored `src/SignatureValidator.sol` currently differs from upstream by two edits. Replace its content with the modified upstream (verbatim) to prove upstream now compiles as-is on v3utils's toolchain. Note upstream imports `@openzeppelin/contracts/interfaces/IERC1271.sol`, which v3utils's `@openzeppelin/=lib/openzeppelin-contracts` remapping resolves to OZ 4.9.6.

```bash
cd ~/projects/v3utils
git submodule update --init --recursive 2>/dev/null || true
cp ~/projects/util-contracts/contracts/SignatureValidator.sol src/SignatureValidator.sol
forge build 2>&1 | tail -8
```

Expected: `Compiler run successful` under solc 0.8.15 / OZ 4.9.6, with no `ECDSA` arity errors. **This is the core proof** that upstream now fits v3utils unmodified.

- [ ] **Step 4: Restore v3utils's vendored file (Task 5 decides the permanent form)**

```bash
cd ~/projects/v3utils && git checkout -- src/SignatureValidator.sol
```

- [ ] **Step 5: Record the verification result**

No commit (no files changed). Note in the task hand-off: "v4utils 0.8.26/OZ5.3.0 ✅, v3utils 0.8.15/OZ4.9.6 ✅ — upstream compiles under both."

---

### Task 5: Remove the v3utils fork (intake)

Make v3utils consume the fixed upstream. **Recommended:** submodule (matches v4utils, eliminates the fork). Alternative in Step-alt if a submodule isn't desired yet. Requires the Task 2/3 commits to be pushed to `KrystalDeFi/util-contracts` first (a submodule pins a remote commit).

**Files:**
- Modify: `~/projects/v3utils/.gitmodules`, `~/projects/v3utils/remappings.txt`, `~/projects/v3utils/foundry.toml`
- Delete: `~/projects/v3utils/src/SignatureValidator.sol`
- Modify: `~/projects/v3utils/src/V3Automation.sol:7` (import path)

**Interfaces:**
- Consumes: `SignatureValidator.isValidSignatureNow(address,bytes32,bytes)` from the upstream package (unchanged signature).
- Produces: nothing downstream.

- [ ] **Step 1 (prerequisite): Push upstream so the submodule can pin it**

```bash
cd ~/projects/util-contracts && git push origin inline-ecdsa-version-agnostic
```

Note the resulting commit SHA (the submodule will pin it). If the branch is merged first, pin the merge commit instead.

- [ ] **Step 2: Add util-contracts as a submodule**

```bash
cd ~/projects/v3utils
git submodule add https://github.com/KrystalDeFi/util-contracts lib/util-contracts
git -C lib/util-contracts checkout <SHA-from-step-1>
git submodule update --init --recursive
```

- [ ] **Step 3: Add the remappings**

Append to `remappings.txt` (mirrors v4utils's nested remapping so upstream's `@openzeppelin` resolves to v3utils's OZ 4.9.6):

```
@krystal/util-contracts/=lib/util-contracts/
lib/util-contracts/:@openzeppelin/=lib/openzeppelin-contracts/
```

- [ ] **Step 4: Delete the vendored fork and its fmt-ignore entry**

```bash
git rm src/SignatureValidator.sol
```

In `foundry.toml`, remove `"src/SignatureValidator.sol"` from the `[fmt] ignore = [...]` array (leave `src/StructHash.sol` and `src/Nfpm.sol` — those stay pinned for their CREATE2 addresses).

- [ ] **Step 5: Update the import in V3Automation.sol (line 7)**

Replace:

```solidity
import { SignatureValidator } from "./SignatureValidator.sol";
```

with:

```solidity
import { SignatureValidator } from "@krystal/util-contracts/contracts/SignatureValidator.sol";
```

- [ ] **Step 6: Build and test v3utils**

Run: `cd ~/projects/v3utils && forge build && forge test`
Expected: builds under solc 0.8.15 / OZ 4.9.6 and the existing v3utils suite passes. (`V3Automation` uses only `SignatureValidator.isValidSignatureNow`, whose signature is unchanged.)

- [ ] **Step 7: Commit**

```bash
git add .gitmodules lib/util-contracts remappings.txt foundry.toml src/V3Automation.sol
git commit -m "refactor: consume @krystal/util-contracts SignatureValidator instead of the vendored fork"
```

**Step-alt (if not using a submodule): keep a zero-diff vendored copy**
- Replace `src/SignatureValidator.sol` content with the modified upstream verbatim (no edits), and update its header comment to state it is now a byte-identical copy (no adaptations needed). Keep the `[fmt] ignore` entry for re-syncability. `forge build && forge test`, then commit. This skips Steps 1–5 and the submodule wiring.

---

## Notes on scope
- `SignatureValidator` is an `internal` (inlined) library — Task 2's change alters the compiled bytecode of any consumer that inlines it (e.g. `V3Automation`, `V4UtilsRouter`), which is expected for a shared-lib change and does **not** affect v3utils's pinned CREATE2 libraries (`StructHash`, `Nfpm`). Redeploy/re-audit consumers per normal release process.
- Tasks 1–4 are the self-contained, provable core (the util-contracts fix + proof it fits both). Task 5 (v3utils fork removal) can be executed separately or deferred; it depends on the upstream commit being available on the remote.
