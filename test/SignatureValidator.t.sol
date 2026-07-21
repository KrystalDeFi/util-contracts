// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { SignatureValidator } from "../contracts/SignatureValidator.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @dev Smart wallet that accepts a raw ECDSA signature over `hash` from a fixed owner key.
contract MockERC1271Wallet {
  bytes4 constant MAGIC = 0x1626ba7e;
  address public immutable owner;
  constructor(address _owner) { owner = _owner; }
  function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
    (address rec, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, sig);
    return (err == ECDSA.RecoverError.NoError && rec == owner) ? MAGIC : bytes4(0xffffffff);
  }
}

/// @dev A Biz-style 7702 delegate: only accepts a signature over an EIP-712-WRAPPED hash, and
///      requires recover(...) == address(this). Etched onto an EOA to simulate 7702.
contract MockWrapped7702Wallet {
  bytes4 constant MAGIC = 0x1626ba7e;
  function wrap(bytes32 hash) public view returns (bytes32) {
    return keccak256(abi.encodePacked("\x19Wrapped:", block.chainid, address(this), hash));
  }
  function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
    (address rec, ECDSA.RecoverError err, ) = ECDSA.tryRecover(wrap(hash), sig);
    return (err == ECDSA.RecoverError.NoError && rec == address(this)) ? MAGIC : bytes4(0xffffffff);
  }
}

contract SignatureValidatorTest is Test {
  bytes32 constant HASH = keccak256("krystal-order-digest");

  function test_eoa_rawSig_valid() public view {
    uint256 pk = 0xA11CE;
    address eoa = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    bytes memory sig = abi.encodePacked(r, s, v);
    assertTrue(SignatureValidator.isValidSignatureNow(eoa, HASH, sig));
  }

  function test_eoa_wrongKey_invalid() public view {
    address eoa = vm.addr(0xA11CE);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, abi.encodePacked(r, s, v)));
  }

  function test_contractWallet_erc1271_valid() public {
    uint256 pk = 0xC0FFEE;
    MockERC1271Wallet w = new MockERC1271Wallet(vm.addr(pk));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    assertTrue(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  function test_contractWallet_wrongKey_invalid() public {
    MockERC1271Wallet w = new MockERC1271Wallet(vm.addr(0xC0FFEE));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // THE 7702 FIX: account has code AND a key; owner signs the RAW hash.
  function test_7702_rawEoaSig_valid_whenErc1271WouldReject() public {
    uint256 pk = 0x7702;
    address acct = vm.addr(pk);
    MockWrapped7702Wallet impl = new MockWrapped7702Wallet();
    vm.etch(acct, address(impl).code); // 7702: code + key at the same address

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH); // raw sig over HASH
    bytes memory rawSig = abi.encodePacked(r, s, v);

    // ERC-1271 leg fails (wallet wants the wrapped hash) → OZ SignatureChecker rejects.
    assertFalse(SignatureChecker.isValidSignatureNow(acct, HASH, rawSig));
    // Our dual-path accepts via the ECDSA leg.
    assertTrue(SignatureValidator.isValidSignatureNow(acct, HASH, rawSig));
  }

  // Same 7702 account, but signing the WRAPPED hash → ERC-1271 leg accepts.
  function test_7702_wrappedSig_valid_viaErc1271() public {
    uint256 pk = 0x7702;
    address acct = vm.addr(pk);
    MockWrapped7702Wallet impl = new MockWrapped7702Wallet();
    vm.etch(acct, address(impl).code);

    bytes32 wrapped = MockWrapped7702Wallet(acct).wrap(HASH);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, wrapped);
    assertTrue(SignatureValidator.isValidSignatureNow(acct, HASH, abi.encodePacked(r, s, v)));
  }

  function test_zeroSigner_invalid() public view {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xA11CE, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(address(0), HASH, abi.encodePacked(r, s, v)));
  }

  function test_garbageSig_invalid() public view {
    address eoa = vm.addr(0xA11CE);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, hex"deadbeef"));
  }

  // A signature whose last 32 bytes equal the 6492 magic but is too short to be a real
  // 6492 wrapper must NOT revert in abi.decode — it must be treated as a normal (invalid) sig.
  function test_malformed6492Suffix_doesNotRevert_returnsFalse() public view {
    address eoa = vm.addr(0xA11CE);
    bytes memory justTheSuffix = abi.encodePacked(SignatureValidator.ERC6492_DETECTION_SUFFIX); // 32 bytes
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, justTheSuffix));
    // A 96-byte body (< the 128 threshold) ending in the suffix is likewise treated as non-6492.
    bytes memory shortBody = abi.encodePacked(bytes32(0), bytes32(0), SignatureValidator.ERC6492_DETECTION_SUFFIX);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, shortBody));
  }
}
