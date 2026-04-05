// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibValidatorStorage, ValidatorStorage} from "../storage/GardenStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ECDSAValidatorFacet
 * @notice ERC-4337 signature validation for ModularGarden.
 * @dev Implements validateUserOp - the function EntryPoint calls
 *      to verify a UserOperation is authorized by the account owner.
 *
 * ARCHITECTURE DECISION - Why a facet, not hardcoded in Diamond:
 *      Putting validateUserOp in a facet means auth logic is swappable.
 *      Today: ECDSA secp256k1 signatures.
 *      Tomorrow: diamondCut to PasskeyValidatorFacet — P-256 WebAuthn.
 *      Future: diamondCut to QuantumValidatorFacet — post-quantum scheme.
 *      No fund movement. No redeployment. One diamondCut call.
 *
 * TWO OWNERS — Why ValidatorStorage.owner != LibDiamond.contractOwner:
 *      contractOwner controls Diamond upgrades — high security, used rarely.
 *      ValidatorStorage.owner controls UserOperation signing — used daily.
 *      Compromising the signing key does not grant upgrade access.
 *      Two independent threat surfaces, independently manageable.
 *
 * PRODUCTION NOTE:
 *      LibDiamond.contractOwner should be a multisig or timelock
 *      before managing real funds. Deployment decision, not code change.
 */
contract ECDSAValidatorFacet {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // EntryPoint v0.7 canonical address - same on all EVM chains
    // Immutable - if EntryPoint upgrades, deploy a new validator facet
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    // Return values for validatUserOp
    // Defined by ERC-4337 spec - do not change these values
    uint256 constant SIG_VALIDATION_SUCCESS = 0;
    uint256 constant SIG_VALIDATION_FAILED = 1;

    // =============================================================
    //                         EVENTS
    // =============================================================

    event ValidatorInitialized(address indexed owner);
    event OwnerUpdated(address indexed previousOwner, address indexed newOwner);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error AlreadyInitialized();
    error ZeroAddress();
    error NotEntryPoint(address caller);
    error NotOwner(address caller);

    // =============================================================
    //                      INITIALIZATION
    // =============================================================

    /**
     * @notice Initialize validator with the signing key owner.
     * @dev Called once via diamondCut _init mechanism.
     *      Sets the address whoes signatures validateUserOp accepts.
     *
     * @param _owner Address that will sign UserOperations.
     *               Can be same as LibDiamond.contractOwner (simple setup)
     *               or different (recommended for production)
     */
    function initializeValidator(address _owner) external {
        LibDiamond.enforceIsContractOwner();
        if (_owner == address(0)) revert ZeroAddress();

        ValidatorStorage storage $ = LibValidatorStorage.get();
        if ($.initialized) revert AlreadyInitialized();

        $.owner = _owner;
        $.initialized = true;

        emit ValidatorInitialized(_owner);
    }

    // =============================================================
    //                    ERC-4337 CORE
    // =============================================================

    /**
     * @notice Validate a UserOperation submitted by a budler.
     * @dev Called by EntryPoint during verification loop.
     *      This is the most security-critical function in the validator.
     *
     * EXECUTION ORDER:
     *
     * 1. Verify caller is EntryPoint
     *      → Only EntryPoint should call validateUserOp.
     *      → If anyone else calls it, they're not running a real validation.
     *      → Prevents signature replay attacks via direct calls.
     *
     * 2. Pay missingFunds to EntryPoint
     *      → EntryPoint pre-reserces gas costs from account's deposit.
     *      → If deposit is short, account must top it up here.
     *      → Must happen BEFORE signature check - EntryPoint requires it.
     *
     * 3. Recover signer from signature
     *      → userOpHash is what the user actually signed.
     *      → keccak256(abi.encode(userOp, entryPoint, chainId))
     *      → ChainId binding prevents cross-chain replay.
     *      → EntryPoint address binding prevents cross-EntryPoint replay.
     *
     * 4. Return success or failure
     *      → NEVER revert - return SIG_VALIDATION_FAILED instead.
     *      → Revert = bundler blacklists your account.
     *
     * @param userOp                The full UserOperation
     * @param userOpHash            Hash of UserOp - what the user signed
     * @param missingAccountFunds    ETH account must send to EntryPoint
     * @return validationData       0 = valid, 1 = invalid
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        // Step 1 — Only EntryPoint can call this
        // Direct calls from EOAs or other contracts are rejected
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint(msg.sender);

        // Step 2 — Pay missingFunds to EntryPoint
        // If account deposit is short, top it up now
        // Miss this → EntryPoint reverts entire bundle → bundler blacklists us
        if (missingAccountFunds > 0) {
            // EntryPoint is msg.sender here — send ETH directly to it
            (bool success,) = payable(ENTRY_POINT).call{value: missingAccountFunds, gas: type(uint256).max}("");
            // Ignore success — EntryPoint handles failure
            (success);
        }

        // Step 3 - Recover signer from signature
        // userOpHash already includes chainId and EntryPoint address
        // so we don't need to add them here - they're baked in
        //
        // WHY tryRecover NOT recover:
        // ECDSA.recover reverts on invalid signatures
        // We must never revert in validateUserOp
        // tryRecover returns address(0) on invalid signature instead
        (address recovered, ECDSA.RecoverError recoverError,) =
            ECDSA.tryRecover(userOpHash.toEthSignedMessageHash(), userOp.signature);

        // If recovery itself failed, return FAILED — don't revert
        if (recoverError != ECDSA.RecoverError.NoError) {
            return SIG_VALIDATION_FAILED;
        }

        // Step 4 — Compare recovered signer to stored owner
        ValidatorStorage storage $ = LibValidatorStorage.get();

        if (recovered == $.owner) {
            return SIG_VALIDATION_SUCCESS;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    // =============================================================
    //                    KEY ROTATION
    // =============================================================

    /**
     * @notice Rotate the signing key without redeploying or diamondCut.
     * @dev Only Diamond owner can rotate the signing key.
     *      Use case: periodic key rotation, suspected compromise.
     *
     * WHY DIAMOND OWNER CONTROLS THIS:
     *      If the signing key is compromised, the attacker cannot
     *      rotate it to lock out the real owner — they don't control
     *      LibDiamond.contractOwner.
     *      Real owner uses their secure key to rotate to a new address.
     *
     * @param _newOwner New signing key address
     */
    function setValidatorOwner(address _newOwner) external {
        LibDiamond.enforceIsContractOwner();
        if (_newOwner == address(0)) revert ZeroAddress();

        ValidatorStorage storage $ = LibValidatorStorage.get();
        address previous = $.owner;

        $.owner = _newOwner;
        emit OwnerUpdated(previous, _newOwner);
    }

    /**
     * @notice Returns the current signing key owner.
     */
    function getValidatorOwner() external view returns (address) {
        return LibValidatorStorage.get().owner;
    }
}
