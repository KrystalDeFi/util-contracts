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

  constructor(address _owner) {
    owner = _owner;
  }

  function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
    (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
    return (err == ECDSA.RecoverError.NoError && rec == owner) ? MAGIC : bytes4(0xffffffff);
  }
}

/// @dev A Biz-style 7702 delegate: only accepts a signature over an EIP-712-WRAPPED hash, and
///      requires recover(...) == address(this). Etched onto an EOA to simulate 7702.
contract RevertingERC1271Wallet {
  function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
    revert("delegate reverted");
  }
}

contract ShortReturnERC1271Wallet {
  // Returns only 4 bytes (the magic value un-padded) instead of a full 32-byte word.
  function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
    assembly ("memory-safe") {
      mstore(0x00, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
      return(0x00, 4)
    }
  }
}

/// @dev Returns the magic value in the first word followed by ~100KB of trailing data. A naive
///      unbounded return-data copy would balloon the CALLER's memory; the bounded ERC-1271 leg copies
///      only the first 32-byte word and still validates.
contract HugeReturnERC1271Wallet {
  function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
    assembly {
      mstore(0x00, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
      // return magic word (0x20) + 100000 bytes of (zero-initialized) trailing blob
      return(0x00, add(0x20, 100000))
    }
  }
}

/// @dev A non-compliant/legacy ERC-1271 wallet that returns `bool true` (returndata word = 0x00..01)
///      instead of the bytes4 magic. Its return word carries non-zero LOW-order bytes, so the previous
///      `abi.decode(ret,(bytes4))` form REVERTS on it (strict ABI padding validation) — the full-word
///      compare must instead return false without reverting.
contract BoolTrueERC1271Wallet {
  function isValidSignature(bytes32, bytes calldata) external pure returns (bool) {
    return true;
  }
}

contract MockWrapped7702Wallet {
  bytes4 constant MAGIC = 0x1626ba7e;

  function wrap(bytes32 hash) public view returns (bytes32) {
    return keccak256(abi.encodePacked("\x19Wrapped:", block.chainid, address(this), hash));
  }

  function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
    (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(wrap(hash), sig);
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

  // HIGH-1 regression: a 6492-tagged signature that is long enough (>=128) but whose ABI offsets are
  // out of bounds must NOT revert in abi.decode — it must be treated as invalid and return false.
  function test_view_malformed6492Body_doesNotRevert_returnsFalse() public view {
    address eoa = vm.addr(0xA11CE);
    // head = [factory=0, offset1=4096 (out of bounds), offset2=0] ++ 6492 suffix => 128 bytes
    bytes memory malformed =
      abi.encodePacked(bytes32(0), bytes32(uint256(4096)), bytes32(0), SignatureValidator.ERC6492_DETECTION_SUFFIX);
    assertEq(malformed.length, 128);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, malformed));
  }

  function test_sideEffects_malformed6492Body_doesNotRevert_returnsFalse() public {
    address eoa = vm.addr(0xA11CE);
    bytes memory malformed =
      abi.encodePacked(bytes32(0), bytes32(uint256(4096)), bytes32(0), SignatureValidator.ERC6492_DETECTION_SUFFIX);
    assertFalse(SignatureValidator.isValidSignatureNowWithSideEffects(eoa, HASH, malformed));
  }

  // HIGH-1 (guard-2): in-bounds offset but a length word larger than the remaining body → false, no revert.
  function test_view_malformed6492OverlongLen_returnsFalse() public view {
    address eoa = vm.addr(0xA11CE);
    // head=[factory=0, off1=0x60, off2=0x60], len word (max) at offset 0x60, + suffix => 160 bytes (bodyLen 128)
    bytes memory malformed = abi.encodePacked(
      bytes32(0),
      bytes32(uint256(0x60)),
      bytes32(uint256(0x60)),
      bytes32(type(uint256).max),
      SignatureValidator.ERC6492_DETECTION_SUFFIX
    );
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, malformed));
  }

  // HIGH-1 (dirty address): a 6492 body whose factory word has dirty high bits → false, no revert.
  function test_view_malformed6492DirtyFactory_returnsFalse() public view {
    address eoa = vm.addr(0xA11CE);
    bytes memory malformed = abi.encodePacked(
      bytes32(uint256(1) << 200), // dirty high bits above the low 160
      bytes32(uint256(0x60)),
      bytes32(uint256(0x60)),
      SignatureValidator.ERC6492_DETECTION_SUFFIX
    );
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, malformed));
  }

  // Fuzzes (signer,hash,sig) through the no-revert view path; fuzzed signers almost never have code,
  // so the ERC-1271 leg is covered by the dedicated reverting/short-return delegate tests below.
  function testFuzz_isValidSignatureNow_neverReverts(address signer, bytes32 hash, bytes memory sig) public view {
    SignatureValidator.isValidSignatureNow(signer, hash, sig); // must return (not revert)
  }

  // Malleability: the high-s counterpart of a valid signature must be rejected (OZ tryRecover guards
  // high-s and v). Locks this behavior against a future dependency swap.
  function test_ecdsa_highSMalleable_rejected() public view {
    uint256 pk = 0xA11CE;
    address eoa = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // secp256k1 curve order N
    // With the correct N, highS = n - s lands in (N/2, N): an s-value the raw ecrecover precompile
    // ACCEPTS (s < N) but OZ's malleability guard REJECTS (s > N/2) — so assertFalse below genuinely
    // proves the guard fires, rather than the signature merely being out of ecrecover's own s<N bound.
    bytes32 highS = bytes32(n - uint256(s));
    uint8 flippedV = v == 27 ? 28 : 27;
    bytes memory malleable = abi.encodePacked(r, highS, flippedV);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, malleable));
  }

  // A delegate whose isValidSignature REVERTS must not bubble up — the ERC-1271 leg yields false and
  // the check falls through to ECDSA (which also fails here) → overall false, no revert.
  function test_erc1271_revertingDelegate_doesNotBubble_returnsFalse() public {
    RevertingERC1271Wallet w = new RevertingERC1271Wallet();
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // A delegate returning <32 bytes must be rejected by the `ret.length >= 32` guard (which prevents an
  // abi.decode revert), falling through to ECDSA → overall false, no revert.
  function test_erc1271_shortReturn_doesNotRevert_returnsFalse() public {
    ShortReturnERC1271Wallet w = new ShortReturnERC1271Wallet();
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // Correctness with large return data: a wallet returning the magic word followed by ~100KB of blob
  // still validates. (This asserts the verdict is preserved, not the copy bound itself — the bound is a
  // property of the bounded `staticcall` in the source; see the dirty-return test below for the
  // behavior change that IS observable from a test.)
  function test_erc1271_hugeReturnData_valid() public {
    HugeReturnERC1271Wallet w = new HugeReturnERC1271Wallet();
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH); // wallet ignores the sig, always returns magic
    assertTrue(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // Never-reverts regression (risk #3, load-bearing): a non-compliant wallet returning `bool true`
  // (returndata 0x00..01) has non-zero low-order bytes. The previous `abi.decode(ret,(bytes4))` form
  // REVERTS on this under strict ABI padding validation — which would break the never-reverts contract.
  // The full-word compare returns false instead, falling through to the ECDSA leg → overall false, no
  // revert. This test REVERTS (fails) under the old form and passes under the bounded full-word compare.
  function test_erc1271_dirtyReturnData_doesNotRevert_returnsFalse() public {
    BoolTrueERC1271Wallet w = new BoolTrueERC1271Wallet();
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH);
    assertFalse(SignatureValidator.isValidSignatureNow(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // Side-effects entry, NON-6492 signature (EOA): the sig is not 6492-tagged, so no external call is
  // made — validation proceeds via the ECDSA leg exactly like the view entry.
  function test_sideEffects_plainEoaSig_valid() public {
    uint256 pk = 0xA11CE;
    address eoa = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    assertTrue(SignatureValidator.isValidSignatureNowWithSideEffects(eoa, HASH, abi.encodePacked(r, s, v)));
  }

  // Side-effects entry, NON-6492 signature (contract wallet): signer has code, not 6492-tagged → the
  // ERC-1271 leg validates and no factory call is made.
  function test_sideEffects_plainContractWallet_valid() public {
    uint256 pk = 0xC0FFEE;
    MockERC1271Wallet w = new MockERC1271Wallet(vm.addr(pk));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    assertTrue(SignatureValidator.isValidSignatureNowWithSideEffects(address(w), HASH, abi.encodePacked(r, s, v)));
  }

  // EIP-2098 compact (64-byte) signatures ARE accepted: the ECDSA leg routes a 64-byte input through
  // OZ tryRecover(bytes32, r, vs), which decodes the compact form and enforces low-s. Accepted via both
  // entries (view + side-effects), matching the 65-byte (r,s,v) verdict for the same key.
  function test_ecdsa_64byteCompactSig_accepted() public {
    uint256 pk = 0xA11CE;
    address eoa = vm.addr(pk);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, HASH);
    bytes32 vs = bytes32((uint256(v - 27) << 255) | uint256(s)); // EIP-2098: yParity in the top bit of s
    bytes memory compact = abi.encodePacked(r, vs);
    assertEq(compact.length, 64);
    // The same key's 65-byte form is also valid — the compact form is just a re-encoding.
    assertTrue(SignatureValidator.isValidSignatureNow(eoa, HASH, abi.encodePacked(r, s, v)));
    assertTrue(SignatureValidator.isValidSignatureNow(eoa, HASH, compact));
    assertTrue(SignatureValidator.isValidSignatureNowWithSideEffects(eoa, HASH, compact));
  }

  // A 64-byte compact signature by the WRONG key must be rejected (recovers a different address).
  function test_ecdsa_64byteCompactSig_wrongKey_invalid() public view {
    address eoa = vm.addr(0xA11CE);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, HASH); // signed by a different key
    bytes32 vs = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory compact = abi.encodePacked(r, vs);
    assertEq(compact.length, 64);
    assertFalse(SignatureValidator.isValidSignatureNow(eoa, HASH, compact));
  }
}

/// @dev CREATE2 factory that deploys a MockERC1271Wallet at a deterministic address. Counts deploy()
///      invocations so tests can assert whether the library did (or did NOT) call it.
contract Mock6492Factory {
  uint256 public deployCount;

  function deploy(bytes32 salt, address owner) external returns (address addr) {
    deployCount++;
    bytes memory code = abi.encodePacked(type(MockERC1271Wallet).creationCode, abi.encode(owner));
    assembly {
      addr := create2(0, add(code, 0x20), mload(code), salt)
    }
  }

  function predict(bytes32 salt, address owner) external view returns (address) {
    bytes32 h = keccak256(
      abi.encodePacked(
        bytes1(0xff),
        address(this),
        salt,
        keccak256(abi.encodePacked(type(MockERC1271Wallet).creationCode, abi.encode(owner)))
      )
    );
    return address(uint160(uint256(h)));
  }
}

contract SignatureValidator6492Test is Test {
  bytes32 constant HASH = keccak256("krystal-order-digest");
  bytes32 constant SALT = bytes32(uint256(1));

  Mock6492Factory factory;
  uint256 ownerPk = 0xC0FFEE;
  address counterfactual;
  bytes wrappedSig;

  function setUp() public {
    factory = new Mock6492Factory();
    counterfactual = factory.predict(SALT, vm.addr(ownerPk));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, HASH);
    bytes memory inner = abi.encodePacked(r, s, v);
    bytes memory factoryCalldata = abi.encodeCall(Mock6492Factory.deploy, (SALT, vm.addr(ownerPk)));
    wrappedSig = abi.encodePacked(
      abi.encode(address(factory), factoryCalldata, inner), SignatureValidator.ERC6492_DETECTION_SUFFIX
    );
  }

  function test_6492_view_beforeDeploy_invalid() public view {
    assertEq(counterfactual.code.length, 0);
    assertFalse(SignatureValidator.isValidSignatureNow(counterfactual, HASH, wrappedSig));
  }

  function test_6492_sideEffects_deploysAndValidates() public {
    assertEq(counterfactual.code.length, 0);
    assertTrue(SignatureValidator.isValidSignatureNowWithSideEffects(counterfactual, HASH, wrappedSig));
    assertGt(counterfactual.code.length, 0); // factory deployed it
  }

  function test_6492_view_afterDeploy_valid() public {
    factory.deploy(SALT, vm.addr(ownerPk)); // account now exists
    assertTrue(SignatureValidator.isValidSignatureNow(counterfactual, HASH, wrappedSig));
  }

  // Side-effects entry with a 6492 wrapper but the signer is ALREADY deployed: the factory-deploy step
  // is skipped (the `signer.code.length == 0` guard is false) and validation proceeds via the unwrapped
  // inner signature through the ERC-1271 leg. Load-bearing: asserts the library did NOT call the factory
  // (deployCount unchanged) — if the has-code guard were removed, the library would re-invoke deploy and
  // the count would increment, failing this test.
  function test_6492_sideEffects_signerHasCode_skipsDeploy_valid() public {
    factory.deploy(SALT, vm.addr(ownerPk)); // account now exists (deployCount -> 1)
    assertGt(counterfactual.code.length, 0);
    uint256 deploysBefore = factory.deployCount();
    assertTrue(SignatureValidator.isValidSignatureNowWithSideEffects(counterfactual, HASH, wrappedSig));
    assertEq(factory.deployCount(), deploysBefore); // factory NOT called: deploy skipped for a coded signer
  }
}
