// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import { SignatureValidator, ISignatureValidatorSingleton } from "./SignatureValidator.sol";

/// @title SignatureValidatorSingleton
/// @notice Stateless, privilege-less singleton that performs the ERC-6492 counterfactual-account deploy
///         in ITS OWN context, then validates. Because the deploy's `factory.call` executes with
///         `msg.sender == this singleton` — a contract that holds no funds, token approvals, or roles —
///         an attacker signature cannot use it to make a privileged/fund-holding consumer call arbitrary
///         targets as itself. This is the ERC-6492 reference `UniversalSigValidator` isolation model:
///         it neutralizes the arbitrary-call-as-consumer drain that an inlined deploy would expose.
///         Deploy ONE instance per chain and route
///         `SignatureValidator.isValidSignatureNowWithSideEffects(validator, ...)` through it.
/// @dev This contract MUST remain stateless and privilege-less — that IS the security property. Never
///      grant it roles or approvals, and never let it hold a token/ETH balance. It has no owner, no
///      storage, and no funds by design; it is safe to share across all consumers on a chain.
contract SignatureValidatorSingleton is ISignatureValidatorSingleton {
  /// @notice Validate `signature` for `signer` over `hash`, deploying a counterfactual (ERC-6492) account
  ///         first if needed. The deploy runs AS this (privilege-less) singleton. Never reverts on an
  ///         invalid signature — returns false.
  /// @dev The factory call target and calldata come from the untrusted signature; because it runs as this
  ///      empty singleton, an arbitrary `factory.call` is harmless (nothing to drain). The deploy is
  ///      best-effort and its result is intentionally ignored — the dual-path check below decides
  ///      validity. Validation is delegated to `SignatureValidator.isValidSignatureNow` (view), which
  ///      unwraps the wrapper and dual-checks the inner signature (the account now has code if deployed).
  function isValidSigWithSideEffects(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
    if (signer == address(0)) return false;
    bytes memory sig = signature; // single calldata->memory copy, reused by the helpers below
    if (SignatureValidator._isERC6492(sig)) {
      (bool okDecode, address factory, bytes memory factoryCalldata,) = SignatureValidator._tryDecodeERC6492(sig);
      if (!okDecode) return false;
      if (signer.code.length == 0 && factory != address(0)) {
        // Deploy AS this singleton; result intentionally ignored — the dual-check decides validity.
        (bool success,) = factory.call(factoryCalldata);
        success;
      }
    }
    return SignatureValidator.isValidSignatureNow(signer, hash, sig);
  }
}
