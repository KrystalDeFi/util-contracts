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
    // Leg 2: ECDSA — attempted EVEN when the signer has code (the EIP-7702 case).
    (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
    return err == ECDSA.RecoverError.NoError && recovered == signer;
  }

  function _isValidERC1271(address signer, bytes32 hash, bytes memory sig) private view returns (bool) {
    (bool ok, bytes memory ret) = signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, sig)));
    return ok && ret.length >= 32 && abi.decode(ret, (bytes4)) == ERC1271_MAGIC_VALUE;
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
