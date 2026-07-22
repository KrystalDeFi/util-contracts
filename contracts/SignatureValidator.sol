// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title SignatureValidator
/// @notice Dual-path signature validation: a signature is accepted if EITHER an ERC-1271 check OR
///         an ECDSA recovery succeeds. Unlike OpenZeppelin/Solady `SignatureChecker`, which selects
///         exactly one path based on `signer.code.length` (no code -> ECDSA, code -> ERC-1271),
///         this library attempts BOTH. That is required for EIP-7702 accounts, which have contract
///         code AND a controlling EOA key: such an account may present a raw EOA signature (ECDSA
///         leg) or a signature its delegate validates via `isValidSignature` (ERC-1271 leg).
///         ERC-6492 wrapped signatures are supported for counterfactual (not-yet-deployed) accounts.
///         NOTE: for an EIP-7702 signer, a valid signature from the account's root EOA key over `hash`
///         is accepted UNCONDITIONALLY via the ECDSA leg, OVERRIDING any restriction the account's own
///         `isValidSignature` would enforce (e.g. wrapped-digest replay protection, session-key scoping,
///         2FA). Consumers relying on a 7702 account's signature policy must account for this.
///         NOTE: the ECDSA leg accepts both 65-byte `(r,s,v)` and 64-byte EIP-2098 `(r,vs)` encodings,
///         which are inter-convertible WITHOUT the signing key. A single authorization therefore has two
///         valid on-chain signature encodings, so `keccak256(signature)` is NOT a stable unique id —
///         consumers MUST do replay protection with nonces or digest/hash invalidation, never by
///         tracking used signature bytes.
library SignatureValidator {
  /// @dev ERC-1271 magic value: `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
  bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

  /// @dev ERC-6492 detection suffix (the last 32 bytes of a wrapped signature).
  bytes32 internal constant ERC6492_DETECTION_SUFFIX =
    0x6492649264926492649264926492649264926492649264926492649264926492;

  /// @notice VIEW dual-path validation. Returns true if `signature` is valid for `signer` via
  ///         ERC-1271 (attempted only when `signer` has code) OR ECDSA recovery (always attempted).
  ///         If `signature` is ERC-6492-wrapped it is unwrapped first; the factory-deploy prepare
  ///         step is NOT performed here (this is a view), so a not-yet-deployed account returns false.
  /// @dev For an EIP-7702 signer the raw root-key ECDSA signature is accepted UNCONDITIONALLY,
  ///      overriding the account's own `isValidSignature` policy — see the contract-level NOTE.
  function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
    if (signer == address(0)) return false;
    bytes memory sig = signature;
    if (_isERC6492(sig)) {
      // The full body is decoded (including `factoryCalldata`, which this view entry does not use)
      // ON PURPOSE: `_tryDecodeERC6492` rejects a wrapper whose factoryCalldata region is malformed, so
      // this view entry and the side-effects entry return the SAME accept/reject verdict for a given
      // wrapper. The extra `factoryCalldata` copy is bounded by the wrapper the caller already supplied.
      (bool okDecode,,, bytes memory inner) = _tryDecodeERC6492(sig);
      if (!okDecode) return false;
      sig = inner;
    }
    return _dualCheck(signer, hash, sig);
  }

  /// @notice NON-VIEW full ERC-6492. If `signature` is 6492-wrapped and `signer` has no code, calls
  ///         `factory` with `factoryCalldata` to deploy the account, then runs the dual-path check.
  ///         Never reverts on an invalid signature; returns false instead.
  /// @dev SECURITY: this makes an arbitrary external call `factory.call(factoryCalldata)` with BOTH the
  ///      target and the calldata taken from the (untrusted) signature, executed from the CALLER's own
  ///      context (this is an inlined internal library). It fires whenever `signer` has no code and
  ///      `factory` is non-zero, BEFORE and INDEPENDENT of the validation result — a returned `false`
  ///      is NOT a safety net. Treat it as an arbitrary-call / reentrancy primitive: callers MUST gate
  ///      it behind a reentrancy guard, MUST NOT invoke it mid-operation while holding funds, approvals,
  ///      or privileged roles, and should only pass signatures from a trusted source. The ERC-6492
  ///      reference isolates this in a stateless singleton validator; this inlined form does not. Prefer
  ///      `isValidSignatureNow` (view, no side effects) unless you specifically need counterfactual
  ///      account deployment.
  /// @custom:precondition A consumer that adopts this function MUST (not "should") call it behind a
  ///      reentrancy guard and MUST NOT hold funds, token approvals, or privileged roles at the call
  ///      site. Adopting it without both is a security defect in the consumer, not a hardening TODO.
  function isValidSignatureNowWithSideEffects(address signer, bytes32 hash, bytes memory signature)
    internal
    returns (bool)
  {
    if (signer == address(0)) return false;
    bytes memory sig = signature;
    if (_isERC6492(sig)) {
      (bool okDecode, address factory, bytes memory factoryCalldata, bytes memory inner) = _tryDecodeERC6492(sig);
      if (!okDecode) return false;
      if (signer.code.length == 0 && factory != address(0)) {
        // Best-effort deploy; result intentionally ignored — the dual-check below decides validity.
        (bool success,) = factory.call(factoryCalldata);
        success;
      }
      sig = inner;
    }
    return _dualCheck(signer, hash, sig);
  }

  // ---------------------------------------------------------------------------------------------
  // internal helpers
  // ---------------------------------------------------------------------------------------------

  function _dualCheck(address signer, bytes32 hash, bytes memory sig) private view returns (bool) {
    // Leg 1: ERC-1271 (only meaningful when the signer has code).
    if (signer.code.length != 0 && _isValidERC1271(signer, hash, sig)) return true;
    // Leg 2: ECDSA — attempted EVEN when the signer has code (the EIP-7702 case). Accepts both a
    // 65-byte (r,s,v) signature and a 64-byte EIP-2098 compact (r,vs) signature; a 64-byte input is
    // routed through OZ's (r,vs) overload. Both overloads enforce low-s malleability rejection and
    // signal failure via RecoverError (they never revert).
    address recovered;
    ECDSA.RecoverError err;
    if (sig.length == 64) {
      bytes32 r;
      bytes32 vs;
      assembly ("memory-safe") {
        // A 64-byte `bytes memory` holds exactly r || vs in its data region [sig+0x20, sig+0x60).
        r := mload(add(sig, 0x20))
        vs := mload(add(sig, 0x40))
      }
      (recovered, err,) = ECDSA.tryRecover(hash, r, vs);
    } else {
      (recovered, err,) = ECDSA.tryRecover(hash, sig);
    }
    return err == ECDSA.RecoverError.NoError && recovered == signer;
  }

  /// @dev ERC-1271 leg. Two properties over the plain `staticcall` + `abi.decode(ret,(bytes4))` form:
  ///      (1) the return-data copy is bounded to a single 32-byte word — a malicious signer returning a
  ///      huge blob cannot force an unbounded memory copy in this (the caller's) context, only the first
  ///      word is brought into memory; and (2) the word is compared in full against `bytes32(MAGIC)` (as
  ///      OZ's `SignatureChecker` does), so a return word carrying the magic in its top 4 bytes but with
  ///      DIRTY low-order bytes — e.g. a non-compliant wallet returning `bool true` (0x00..01) — yields
  ///      `false` here instead of REVERTING inside `abi.decode` (which enforces strict ABI padding),
  ///      preserving the library's never-reverts contract. For a well-formed wallet the verdict is
  ///      unchanged: (call succeeded, >= 32 bytes returned, first returned word == magic).
  function _isValidERC1271(address signer, bytes32 hash, bytes memory sig) private view returns (bool) {
    bytes memory cd = abi.encodeCall(IERC1271.isValidSignature, (hash, sig));
    bytes32 word;
    assembly ("memory-safe") {
      // Copy at most 32 bytes of return data into scratch (0x00). `word` is loaded only when the call
      // succeeded AND returned a full word, so a partial (<32-byte) or empty return leaves it at zero.
      let ok := staticcall(gas(), signer, add(cd, 0x20), mload(cd), 0x00, 0x20)
      if and(ok, iszero(lt(returndatasize(), 0x20))) { word := mload(0x00) }
    }
    return word == bytes32(ERC1271_MAGIC_VALUE);
  }

  function _isERC6492(bytes memory sig) private pure returns (bool) {
    // A 6492 wrapper needs a 32-byte suffix plus at least a 96-byte ABI head; shorter inputs cannot be
    // 6492 wrappers. (Out-of-bounds offsets in a long-enough body are handled by _tryDecodeERC6492.)
    if (sig.length < 128) return false;
    bytes32 suffix;
    assembly ("memory-safe") {
      suffix := mload(add(add(sig, 0x20), sub(mload(sig), 32)))
    }
    return suffix == ERC6492_DETECTION_SUFFIX;
  }

  /// @dev Bounds-checked decode of an ERC-6492 wrapper body `abi.encode(address, bytes, bytes)`.
  ///      Returns ok=false (NEVER reverts) if the body is malformed — so a crafted signature cannot
  ///      force `abi.decode` to revert and break the "never reverts" contract. `sig` is assumed
  ///      6492-tagged with `sig.length >= 128` (guaranteed by `_isERC6492`).
  function _tryDecodeERC6492(bytes memory sig)
    private
    pure
    returns (bool ok, address factory, bytes memory factoryCalldata, bytes memory inner)
  {
    // Defensive: callers guard via _isERC6492, but keep this self-contained (also prevents the
    // `sig.length - 32` below from underflow-reverting on a short input).
    if (sig.length < 128) return (false, address(0), "", "");
    uint256 bodyLen = sig.length - 32; // >= 96 (three 32-byte head words)
    uint256 base;
    assembly ("memory-safe") {
      base := add(sig, 0x20) // the body occupies the first `bodyLen` bytes of sig's data
    }
    uint256 word0;
    uint256 off1;
    uint256 off2;
    assembly ("memory-safe") {
      word0 := mload(base)
      off1 := mload(add(base, 0x20))
      off2 := mload(add(base, 0x40))
    }
    if (word0 >> 160 != 0) return (false, address(0), "", ""); // dirty address high bits
    // Safe: the guard above proves the high 96 bits of `word0` are zero, so the uint160 narrowing
    // cannot truncate. (forge-lint cannot see the guard, so the cast is silenced explicitly.)
    // forge-lint: disable-next-line(unsafe-typecast)
    factory = address(uint160(word0));

    bool ok1;
    (ok1, factoryCalldata) = _readTailBytes(base, bodyLen, off1);
    if (!ok1) return (false, address(0), "", "");
    bool ok2;
    (ok2, inner) = _readTailBytes(base, bodyLen, off2);
    if (!ok2) return (false, address(0), "", "");
    ok = true;
  }

  /// @dev Reads a `bytes` field located at `off` within the `bodyLen`-byte region starting at memory
  ///      pointer `base`, with full bounds checks. Returns ok=false (no revert) on any inconsistency.
  ///      INVARIANT: bytes beyond `len` in the final word of `out` MAY BE DIRTY — the word-copy below
  ///      overwrites the zero-padding that `new bytes(len)` created with adjacent source bytes. Every
  ///      current consumer reads `out` by length only (`factory.call` uses the exact length,
  ///      `abi.encodeCall` re-pads by length, the ECDSA leg reads fixed offsets), so this is unobserved.
  ///      A future consumer that hashes or full-word-compares `out` MUST NOT rely on clean tail padding.
  function _readTailBytes(uint256 base, uint256 bodyLen, uint256 off) private pure returns (bool ok, bytes memory out) {
    // length word must be fully in-bounds: off + 32 <= bodyLen (overflow-safe form)
    if (off > bodyLen || bodyLen - off < 0x20) return (false, "");
    uint256 len;
    assembly ("memory-safe") {
      len := mload(add(base, off))
    }
    uint256 dataStart = off + 0x20;
    // data must be fully in-bounds: dataStart + len <= bodyLen (overflow-safe form)
    if (len > bodyLen - dataStart) return (false, "");
    out = new bytes(len);
    assembly ("memory-safe") {
      let src := add(base, dataStart)
      let dst := add(out, 0x20)
      for { let i := 0 } lt(i, len) { i := add(i, 0x20) } { mstore(add(dst, i), mload(add(src, i))) }
    }
    ok = true;
  }
}
