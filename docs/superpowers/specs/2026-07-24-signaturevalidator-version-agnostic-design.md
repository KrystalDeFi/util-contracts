# Design: Make `SignatureValidator` version-agnostic (inline ECDSA recovery)

**Date:** 2026-07-24
**Repo:** `util-contracts` (`@krystal/util-contracts`)
**Status:** Approved for planning

## Problem

`util-contracts` cannot be consumed directly by both downstream repos:

| Repo    | solc     | OpenZeppelin | Consumes                             |
|---------|----------|--------------|--------------------------------------|
| util-contracts (upstream) | 0.8.28 (foundry), pragma `^0.8.20` | 5.x | — |
| v3utils | 0.8.15   | 4.9.6        | `SignatureValidator.isValidSignatureNow` (view) |
| v4utils | 0.8.26   | 5.3.0        | `SignatureValidator.isValidSignatureNow` (view) |

Because upstream can't compile under v3utils's toolchain, v3utils carries a **vendored fork** of
`src/SignatureValidator.sol` with two documented edits. There are exactly two blockers:

1. **Pragma** `^0.8.20` excludes solc 0.8.15.
2. **`ECDSA.tryRecover` arity** — OZ 4.9.6 returns `(address, RecoverError)` (2 values); OZ 5.x returns
   `(address, RecoverError, bytes32)` (3 values). Solidity tuple destructuring must match arity exactly,
   so no single `ECDSA.tryRecover` call site compiles under both OZ versions.

Neither consumer uses `SignatureValidatorSingleton`; both use only the `isValidSignatureNow` view path.
`IERC1271` and the `ECDSA.RecoverError` enum are path/shape-stable across OZ 4.9 and 5.x — only
`tryRecover`'s arity differs.

## Goal

Make the upstream `SignatureValidator` compile unmodified under **both** toolchains (0.8.15/OZ4.9.6 and
0.8.26/OZ5.3.0), so v3utils no longer needs a fork. Preserve the library's exact current behavior,
including low-`s` malleability rejection.

## Decision: inline ECDSA recovery

`SignatureValidator` already hand-rolls all signature parsing in assembly (the 64-byte EIP-2098 split,
the ERC-1271 staticcall, the ERC-6492 decode). It delegates only the final recovery tail to OZ. We
replace that tail with an internal recovery routine that inlines OZ's exact logic, and drop the OZ ECDSA
import entirely.

Approaches considered and rejected:
- **Solady ECDSA** — pragma `^0.8.4` and a single-return `tryRecover` would fix the version problem, but
  Solady **deliberately does not check malleability** (its ECDSA header: "does NOT check if a signature
  is non-malleable"). Adopting it would silently widen the library's accept set (upper-half-`s`
  signatures pass) and diverge from the OZ `SignatureChecker` parity the code advertises. It also *adds*
  a dependency to both util-contracts and v3utils (extra submodule + nested remapping) rather than
  removing one. To keep today's behavior on Solady you'd re-add the low-`s` check anyway — the same code
  inlining already provides.
- **Upgrade v3utils to 0.8.20 + OZ5** — fixes it from the other side, but a solc bump alone doesn't
  resolve the arity issue (OZ5 migration is also required: `security/Pausable`→`utils/Pausable`,
  `AccessControl`, `SafeERC20.safeApprove` removal), changes deployed automation-contract bytecode, and
  needs the pinned CREATE2 libs (`StructHash`, `Nfpm`) pinned to 0.8.15. Much larger blast radius.
- **Keep the vendored fork** — the status quo we're removing.

## Changes

### 1. `contracts/SignatureValidator.sol`
- Pragma `^0.8.20` → `^0.8.15`. (Truthful floor, verified by build: solc 0.8.13 FAILS — `abi.encodeCall`
  won't implicitly convert the `bytes memory` arg to the interface's `bytes calldata` until 0.8.14, and
  `assembly ("memory-safe")` needs ≥0.8.13 — so the real minimum is 0.8.14; `^0.8.15` is chosen because
  0.8.15 is v3utils's actual solc and is the lowest version the tri-toolchain CI build exercises, so every
  advertised version is guarded.)
- Remove `import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";`.
- Keep `import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";` (stable across OZ
  4.9/5.x).
- In `_dualCheck`, replace both `ECDSA.tryRecover(...)` call sites and the `ECDSA.RecoverError` logic with
  a private `_tryRecover` that inlines OZ's tail verbatim:
  - Accept only 65-byte `(r,s,v)` and 64-byte EIP-2098 `(r,vs)` inputs; any other length → failure
    (returns `address(0)`), matching OZ's `InvalidSignatureLength`.
  - For 64-byte: `s = vs & 0x7fff...ffff`, `v = uint8((uint256(vs) >> 255) + 27)`.
  - Reject upper-half `s`: `if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);`
    (OZ's exact malleability constant, copied verbatim).
  - `address signer = ecrecover(hash, v, r, s);` — `ecrecover` returns `address(0)` for `v ∉ {27,28}` and
    other failures, so a single `signer == address(0)` check covers the invalid-`v` and invalid-signature
    cases.
  - `_dualCheck` accepts the ECDSA leg iff `recovered != address(0) && recovered == signer`. (The
    top-level `signer == address(0)` guard in `isValidSignatureNow` already rejects a zero signer up
    front, so a zero `ecrecover` result can never spuriously match.)
- No behavioral change to the ERC-1271 leg, ERC-6492 decode, or the never-reverts contract.

### 2. `contracts/SignatureValidatorSingleton.sol`
- Pragma `^0.8.20` → `^0.8.15` (same floor as the library — it inlines the library's memory-safe
  assembly, so it cannot compile below 0.8.14 either). No OZ ECDSA usage (imports only the local
  `SignatureValidator`).

### 3. Package metadata
- `package.json`: relax `@openzeppelin/contracts` from `>=5.2.0 <6.0.0` to `>=4.9.0 <6.0.0` — only
  `IERC1271` is used now, present since OZ 4.x.
- `foundry.toml`: no change required (util-contracts' own build stays on 0.8.28/OZ5 for its test suite);
  the pragma is what governs downstream consumption.

### 4. Tests — `test/SignatureValidator.t.sol` (OZ-style ECDSA coverage)
Mirror OpenZeppelin's `ECDSA.test.js` cases, exercised through `SignatureValidator.isValidSignatureNow`
with an EOA signer (no code → pure ECDSA leg):
- **Valid 65-byte `(r,s,v)`** signature from a known key → accepted; wrong signer → rejected.
- **Valid 64-byte EIP-2098 `(r,vs)`** compact form of the same signature → accepted (proves the 64-byte
  branch and `vs` split).
- **Malleability:** given a valid signature, flip to the upper-half `s` (`s' = n - s`) and the
  complementary `v` → **rejected** (this is the behavior Solady would have silently dropped).
- **Wrong length:** 0, 63, 66, empty → rejected, no revert.
- **`v` handling:** raw `v ∈ {0,1}` (not 27/28) → rejected (ecrecover yields `address(0)`).
- **Zero signer:** `isValidSignatureNow(address(0), ...)` → false.
- **Differential fuzz:** for random `(privateKey, hash)`, sign and assert the inline result matches OZ's
  `ECDSA.tryRecover` verdict (accept ⇔ `RecoverError.NoError` && same recovered address), and that a
  malleated variant is rejected by both. util-contracts' own test toolchain (0.8.28/OZ5) keeps OZ
  available as the oracle.

Existing ERC-1271 / ERC-6492 / singleton tests remain and must continue to pass unchanged.

### 5. Downstream: v3utils consumption
After upstream compiles on 0.8.15/OZ4.9.6, replace v3utils's vendored `src/SignatureValidator.sol`.
**Default (recommended):** add `util-contracts` as a `lib/` submodule (as v4utils does) with a nested
remapping `lib/util-contracts/:@openzeppelin/=lib/openzeppelin-contracts/` so `IERC1271` resolves to
v3utils's OZ 4.9.6; delete the vendored file and its `[fmt] ignore` entry. Alternative: keep a vendored
copy but byte-identical (zero edits). Either way, `SignatureValidator` is an `internal` (inlined)
library — this does not touch the pinned CREATE2 libraries (`StructHash`, `Nfpm`), but it does change
`V3Automation`'s compiled bytecode (expected for any shared-lib change; redeploy/re-audit as usual).
*(This step can be split into its own change if preferred; the util-contracts fix is the primary
deliverable.)*

## Acceptance criteria (tri-toolchain verification)
1. `util-contracts`: `forge build` + `forge test` pass on its own toolchain (0.8.28/OZ5), including the
   new OZ-style ECDSA tests.
2. `v3utils`: builds against the fixed util-contracts on **solc 0.8.15 / OZ 4.9.6** with no source edits
   to the shared file.
3. `v4utils`: still builds against the fixed util-contracts on **solc 0.8.26 / OZ 5.3.0**.

## Non-goals
- Upgrading v3utils's solc or OZ version.
- Changing the ERC-1271, ERC-6492, or singleton logic.
- Any change to the library's public behavior beyond removing the OZ ECDSA dependency (accept set stays
  identical, including low-`s` rejection).
