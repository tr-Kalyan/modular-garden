// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {DiamondDeployer} from "../helpers/DiamondDeployer.sol";
import {Diamond} from "../../src/Diamond.sol";
import {ECDSAValidatorFacet} from "../../src/facets/ECDSAValidatorFacet.sol";
import {LibDiamond} from "../../src/libraries/LibDiamond.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ValidatorTest
 * @notice Unit tests for ECDSAValidatorFacet.
 *
 * WHAT WE PROVE:
 * 1. Initialization sets owner correctly
 * 2. Cannot initialize twice
 * 3. Valid signature returns SIG_VALIDATION_SUCCESS
 * 4. Invalid signature returns SIG_VALIDATION_FAILED — never reverts
 * 5. Wrong signer returns SIG_VALIDATION_FAILED
 * 6. Only EntryPoint can call validateUserOp
 * 7. Owner can rotate signing key
 * 8. Attacker cannot rotate signing key
 */
contract ValidatorTest is Test {
    using MessageHashUtils for bytes32;

    // =============================================================
    //                         STATE
    // =============================================================

    DiamondDeployer deployer;
    Diamond diamond;
    ECDSAValidatorFacet validator;

    // Owner keypair — generated deterministically for tests
    // vm.addr(privateKey) derives the address from the private key
    uint256 ownerPrivateKey = 0xA11CE;
    address owner;

    uint256 attackerPrivateKey = 0xBAD;
    address attacker;

    address entryPoint = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    // =============================================================
    //                         SETUP
    // =============================================================

    function setUp() public {
        // Derive addresses from private keys
        owner = vm.addr(ownerPrivateKey);
        attacker = vm.addr(attackerPrivateKey);

        deployer = new DiamondDeployer();
        diamond = deployer.deploy(owner);

        validator = ECDSAValidatorFacet(address(diamond));

        // Initialize validator with owner
        vm.prank(owner);
        validator.initializeValidator(owner);
    }

    // =============================================================
    //                    INITIALIZATION TESTS
    // =============================================================

    /**
     * @notice Validator owner set correctly after initialization.
     */
    function test_InitializationSetsOwner() public {
        assertEq(validator.getValidatorOwner(), owner);
    }

    /**
     * @notice Cannot initialize twice.
     */
    function test_Revert_CannotInitializeTwice() public {
        vm.expectRevert(abi.encodeWithSelector(ECDSAValidatorFacet.AlreadyInitialized.selector));
        vm.prank(owner);
        validator.initializeValidator(owner);
    }

    /**
     * @notice Attacker cannot initialize validator.
     */
    function test_Revert_AttackerCannotInitialize() public {
        DiamondDeployer freshDeployer = new DiamondDeployer();
        Diamond freshDiamond = freshDeployer.deploy(owner);
        ECDSAValidatorFacet freshValidator = ECDSAValidatorFacet(address(freshDiamond));

        vm.expectRevert(abi.encodeWithSelector(LibDiamond.NotContractOwner.selector, attacker, owner));
        vm.prank(attacker);
        freshValidator.initializeValidator(attacker);
    }

    // =============================================================
    //                    VALIDATION TESTS
    // =============================================================

    /**
     * @notice Valid signature from owner returns SIG_VALIDATION_SUCCESS.
     * @dev This is the happy path — owner signs, EntryPoint validates.
     *
     * HOW WE BUILD A VALID SIGNATURE:
     * 1. Construct a userOpHash (normally EntryPoint computes this)
     * 2. Apply EthSignedMessageHash prefix
     * 3. Sign with owner's private key using vm.sign
     * 4. Pass to validateUserOp
     */
    function test_ValidSignatureReturnsSuccess() public {
        // Build a mock userOpHash
        bytes32 userOpHash = keccak256("test userOp hash");

        // Sign it with owner's private key
        // vm.sign applies toEthSignedMessageHash internally
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build minimal PackedUserOperation
        PackedUserOperation memory userOp = _buildUserOp(address(diamond), signature);

        // Call validateUserOp as EntryPoint
        vm.prank(entryPoint);
        uint256 result = validator.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 0, "Valid signature should return SIG_VALIDATION_SUCCESS");
    }

    /**
     * @notice Invalid signature returns SIG_VALIDATION_FAILED — never reverts.
     * @dev This is the critical safety test.
     *      If validateUserOp reverts, bundler blacklists the account.
     *      Must return 1, not revert.
     */
    function test_InvalidSignatureReturnsFailed() public {
        bytes32 userOpHash = keccak256("test userOp hash");

        // Pass garbage bytes as signature
        bytes memory badSignature = bytes("this is not a valid signature");

        PackedUserOperation memory userOp = _buildUserOp(address(diamond), badSignature);

        // Must NOT revert — must return SIG_VALIDATION_FAILED
        vm.prank(entryPoint);
        uint256 result = validator.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Invalid signature should return SIG_VALIDATION_FAILED");
    }

    /**
     * @notice Wrong signer returns SIG_VALIDATION_FAILED.
     * @dev Attacker signs with their key — should fail.
     *      Recovered address != stored owner → FAILED.
     */
    function test_WrongSignerReturnsFailed() public {
        bytes32 userOpHash = keccak256("test userOp hash");

        // Sign with ATTACKER's private key — not owner's
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPrivateKey, ethSignedHash);
        bytes memory attackerSignature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = _buildUserOp(address(diamond), attackerSignature);

        vm.prank(entryPoint);
        uint256 result = validator.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Wrong signer should return SIG_VALIDATION_FAILED");
    }

    /**
     * @notice Only EntryPoint can call validateUserOp.
     * @dev Direct calls from EOAs or other contracts are rejected.
     *      Prevents signature replay via direct calls.
     */
    function test_Revert_OnlyEntryPointCanValidate() public {
        bytes32 userOpHash = keccak256("test userOp hash");
        PackedUserOperation memory userOp = _buildUserOp(address(diamond), bytes(""));

        vm.expectRevert(abi.encodeWithSelector(ECDSAValidatorFacet.NotEntryPoint.selector, attacker));

        vm.prank(attacker);
        validator.validateUserOp(userOp, userOpHash, 0);
    }

    // =============================================================
    //                    KEY ROTATION TESTS
    // =============================================================

    /**
     * @notice Owner can rotate signing key.
     * @dev New key takes effect immediately on next validateUserOp.
     */
    function test_OwnerCanRotateSigningKey() public {
        address newSigner = vm.addr(0xC0FFEE);

        vm.prank(owner);
        validator.setValidatorOwner(newSigner);

        assertEq(validator.getValidatorOwner(), newSigner);
    }

    /**
     * @notice After rotation, old key is invalid.
     * @dev Old owner can no longer sign valid UserOperations.
     */
    function test_OldKeyInvalidAfterRotation() public {
        // Rotate to new key
        uint256 newPrivateKey = 0xC0FFEE;
        address newSigner = vm.addr(newPrivateKey);

        vm.prank(owner);
        validator.setValidatorOwner(newSigner);

        // Try to validate with OLD key — should fail
        bytes32 userOpHash = keccak256("test userOp hash");
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, ethSignedHash);
        bytes memory oldSignature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = _buildUserOp(address(diamond), oldSignature);

        vm.prank(entryPoint);
        uint256 result = validator.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Old key should be invalid after rotation");
    }

    /**
     * @notice Attacker cannot rotate signing key.
     * @dev If attacker could rotate, they'd lock out the real owner.
     */
    function test_Revert_AttackerCannotRotateKey() public {
        vm.expectRevert(abi.encodeWithSelector(LibDiamond.NotContractOwner.selector, attacker, owner));

        vm.prank(attacker);
        validator.setValidatorOwner(attacker);
    }

    // =============================================================
    //                         HELPERS
    // =============================================================

    /**
     * @notice Build a minimal PackedUserOperation for testing.
     * @dev Most fields are zero — we only care about sender and signature
     *      for validator tests.
     */
    function _buildUserOp(address sender, bytes memory signature) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: bytes(""),
            signature: signature
        });
    }
}
