// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibRiskParams} from "../libraries/LibRiskParams.sol";
import {LibManagerStorage, ManagerStorage} from "../storage/GardenStorage.sol";

/**
 * @title ManagerFacet
 * @notice Manages who can execute strategies and enforces the risk cage.
 * @dev The bridge between the manager (human or AI) and DeFi protocols.
 *      Every execution goes through here. Nothing bypasses it.
 *
 * SECURITY MODEL:
 *  1. Only owner sets/revokes the manager address
 *  2. Only manager can call execute()
 *  3. execute() enforces all risk params via LibRiskParams BEFORE
 *     touching any external protocol
 *  4. State updated before external call - reentrancy protected
 *
 * AI AGENT NOTE (ERC-8004 alignment):
 * The manager address can be held by an AI agent's key.
 * The agent operates autonomously but cannot exceed the risk parameters
 * the owner set. On-chain enforcement — not off-chain trust.
 * This is the primitive for trustless AI-managed portfolios.
 */
contract ManagerFacet {
    // =============================================================
    //                         EVENTS
    // =============================================================

    event ManagerSet(address indexed previousManager, address indexed newManager);
    event ManagerRevoked(address indexed manager);
    event ExecutionSuccess(address indexed manager, address indexed protocol, uint256 value, bytes data);
    event ExecutionFailed(address indexed manager, address indexed protocol, bytes reason);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error NotManager(address caller);
    error AlreadyInitialized();
    error ZeroAddress();
    error ExecutionReverted(bytes reason);

    // =============================================================
    //                      INITIALIZATION
    // =============================================================

    /**
     * @notice Initialize ManagerFacet storage.
     * @dev Called once via diamondCut _init mechanism.
     *      Sets the initial manager address.
     *
     * @param _manager Initial manager address.
     *                 Can ba same as owner (self-managed Garden)
     *                 or a separate address (delegated management)
     */
    function initializeManager(address _manager) external {
        LibDiamond.enforceIsContractOwner();

        if (_manager == address(0)) revert ZeroAddress();

        ManagerStorage storage $ = LibManagerStorage.get();
        if ($.initialized) revert AlreadyInitialized();

        $.manager = _manager;
        $.initialized = true;

        emit ManagerSet(address(0), _manager);
    }

    // =============================================================
    //                    OWNER — MANAGE MANAGER
    // =============================================================

    /**
     * @notice Set a new manager address.
     * @dev Only owner. Replaces existing manager immediately.
     *      Old manager loses all execution rights in the same block.
     *
     * USE CASES:
     *  - Switch from self-managed to AI agent
     *  - Rotate manager key after compromise suspicion
     *  - Hand off to a new strategy executor
     *
     * @param _newManager New Manager address
     */
    function setManager(address _newManager) external {
        LibDiamond.enforceIsContractOwner();
        if (_newManager == address(0)) revert ZeroAddress();

        ManagerStorage storage $ = LibManagerStorage.get();
        address previous = $.manager;

        $.manager = _newManager;
        emit ManagerSet(previous, _newManager);
    }

    /**
     * @notice Revoke manager access entirely.
     * @dev Sets manager to address(0). No address can execute until
     *      a new manager is set. Emergency freeze mechanism.
     *
     * SECURITY NOTE:
     * Two ways to freeze manager activity:
     * 1. setDailySpendLimit(0) in RiskParamsFacet — soft freeze
     * 2. revokeManager() here — hard freeze, no execution possible
     * Use (2) if manager key is compromised.
     */
    function revokeManager() external {
        LibDiamond.enforceIsContractOwner();

        ManagerStorage storage $ = LibManagerStorage.get();
        address previous = $.manager;

        $.manager = address(0);
        emit ManagerRevoked(previous);
    }

    // =============================================================
    //                    MANAGER — EXECUTE
    // =============================================================

    /**
     * @notice Execute a DeFi action on a whitelisted protocol.
     * @dev The most security-critical function in the project
     *
     * EXECUTION ORDER - every step has a reson:
     *
     * 1. Check caller is manager
     *      → Cheapest check. Revert immediately if wrong caller.
     *
     * 2. LibRiskParams.enforceAndRecord()
     *      → Checks protocol whitelist
     *      → Checks maxPositionSize
     *      → Checks daily limit
     *      → Updates dailySpent (BEFORE external call - CEI pattern)
     *
     * 3. Execute the call
     *      → Only after all the checks pass and state is updated
     *      → Forward msg.value so ETH can be sent to protocols
     *
     * 4. Handle result
     *      → Emit success or decode and emit failure reason
     *
     * WHY NOT REVERT ON EXECUTION FAILURE:
     * Refunding spend on revert creates an exploit - manager deliberately
     * passes bad calldata to reset their counter, then executes
     * the real transaction. Counting failed attempts prevents this.
     * Owner observes ExecutionFailed events and adjusts limits manually
     * if legitimate failures occur
     * @param _protocol   Whitelisted protocol to call (Aave, Uniswap etc)
     * @param _data       Encoded function call (e.g. deposit(amount))
     * @param _value      ETH to send with the call
     */
    function execute(address _protocol, bytes calldata _data, uint256 _value) external payable {
        //Checks - 1. Caller must be manager
        ManagerStorage storage $ = LibManagerStorage.get();
        if (msg.sender != $.manager) revert NotManager(msg.sender);

        // Checks + Effects - 2. Enforce risk params and record spend
        // This updates dailySpent BEFORE the external call
        // Reentrancy cannot explout a stale dailySpent value
        LibRiskParams.enforceAndRecord(_value, _protocol);

        // Interactions - 3. Execute the call
        (bool success, bytes memory reason) = _protocol.call{value: _value}(_data);

        // 4. Handle result
        if (success) {
            emit ExecutionSuccess(msg.sender, _protocol, _value, _data);
        } else {
            emit ExecutionFailed(msg.sender, _protocol, reason);
        }
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    /**
     * @notice Returns the current manager address.
     * @dev address(0) means no manager is set — Garden is frozen.
     */
    function getManager() external view returns (address) {
        return LibManagerStorage.get().manager;
    }

    /**
     * @notice Check if an address is the current manager.
     * @param _address Address to check
     */
    function isManager(address _address) external view returns (bool) {
        return LibManagerStorage.get().manager == _address;
    }
}
