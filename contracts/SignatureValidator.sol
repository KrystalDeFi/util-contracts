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
  function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
    internal
    view
    returns (bool)
  {
    if (signer == address(0)) return false;
    bytes memory sig = signature;
    if (_isERC6492(sig)) {
      (,, bytes memory inner) = _decodeERC6492(sig);
      sig = inner;
    }
    return _dualCheck(signer, hash, sig);
  }

  /// @notice NON-VIEW full ERC-6492. If `signature` is 6492-wrapped and `signer` has no code, calls
  ///         `factory` with `factoryCalldata` to deploy the account, then runs the dual-path check.
  ///         Never reverts on an invalid signature; returns false instead.
  function isValidSignatureNowWithSideEffects(address signer, bytes32 hash, bytes memory signature)
    internal
    returns (bool)
  {
    if (signer == address(0)) return false;
    bytes memory sig = signature;
    if (_isERC6492(sig)) {
      (address factory, bytes memory factoryCalldata, bytes memory inner) = _decodeERC6492(sig);
      if (signer.code.length == 0 && factory != address(0)) {
        // Best-effort deploy; if it fails the dual-path below simply returns false.
        (bool ok,) = factory.call(factoryCalldata);
        ok;
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
    (bool ok, bytes memory ret) =
      signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, sig)));
    return ok && ret.length >= 32 && abi.decode(ret, (bytes4)) == ERC1271_MAGIC_VALUE;
  }

  function _isERC6492(bytes memory sig) private pure returns (bool) {
    if (sig.length < 32) return false;
    bytes32 suffix;
    assembly {
      suffix := mload(add(add(sig, 0x20), sub(mload(sig), 32)))
    }
    return suffix == ERC6492_DETECTION_SUFFIX;
  }

  function _decodeERC6492(bytes memory sig)
    private
    pure
    returns (address factory, bytes memory factoryCalldata, bytes memory inner)
  {
    uint256 bodyLen = sig.length - 32;
    bytes memory body = new bytes(bodyLen);
    assembly {
      let src := add(sig, 0x20)
      let dst := add(body, 0x20)
      for { let i := 0 } lt(i, bodyLen) { i := add(i, 0x20) } { mstore(add(dst, i), mload(add(src, i))) }
    }
    (factory, factoryCalldata, inner) = abi.decode(body, (address, bytes, bytes));
  }
}
