// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibRiskParamsStorage, RiskParamsStorage} from "../storage/GardenStorage.sol";

/**
 * @title RiskParamsFacet
 * @notice Defines and enforces the rules a manager must operate within.
 * @dev The "cage" facet. Owner sets constraints. ManagerFacet enforces them.
 *
 * SECURITY MODEL:
 * - Only owner can set risk parameters
 * - LibRiskParams.enforceAndRecord() is called by ManagerFacet before every execution
 * - Manager never touces risk accounting directly
 * - Daily limit resets automatically based on timestamp - no manual reset needed
 *
 * DESIGN DECISION - why timestamp-based reset instead of block-based:
 * Block-based resets (every N blocks) are predictable and gameable.
 * A manager can time transactions to startddle block boundaries and
 * effectively double thier limit. Timestamp-based resets tied to
 * 24-hour winodws are harder to game and more intuitive for users.
 */
contract RiskParamsFacet {
    // =============================================================
    //                         EVENTS
    // =============================================================
    event DailySpendLimitSet(uint256 oldLimit, uint256 newLimit);
    event MaxPositionSizeSet(uint256 oldSize, uint256 newSize);
    event ProtocolAllowed(address indexed protocol);
    event ProtocolRemoved(address indexed protocol);
    event RiskParamsInitialized(uint256 dailySpendLimit, uint256 maxPositionSize);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error AlreadyInitialized();

    // =============================================================
    //                      INITIALIZATION
    // =============================================================
    /**
     * @notice Initialize RiskParams storage with default values.
     * @dev Called once via diamondCut _init mechanism.
     *      Never callable again - initialized flad prevents it.
     *
     * WHY NOT A CONSTRUCTOR:
     *  This runs via delegatecall from the Diamond after the facet
     *  is registered. Constructors don't run in proxy context.
     *  This is the proxy-safe alternative.
     *
     * @param _dailySpendLimit Max ETH a manager can spend in 24hrs
     * @param _maxPositionSize Max ETH in a single transaction
     * @param _allowedProtocols Initial whitelist of protocol addresses
     */
    function initializeRiskParams(
        uint256 _dailySpendLimit,
        uint256 _maxPositionSize,
        address[] calldata _allowedProtocols
    ) external {
        // Only owner can initialize
        LibDiamond.enforceIsContractOwner();

        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        // Re-initialization guard
        if ($.initialized) revert AlreadyInitialized();

        $.dailySpendLimit = _dailySpendLimit;
        $.maxPositionSize = _maxPositionSize;
        $.lastResetTimestamp = block.timestamp;
        $.initialized = true;

        // Whitelist each protocol in the initial set
        for (uint256 i; i < _allowedProtocols.length;) {
            $.allowedProtocols[_allowedProtocols[i]] = true;
            emit ProtocolAllowed(_allowedProtocols[i]);
            unchecked {
                ++i;
            }
        }
        emit RiskParamsInitialized(_dailySpendLimit, _maxPositionSize);
    }

    // =============================================================
    //                    OWNER — SET PARAMS
    // =============================================================

    /**
     * @notice Update the daily spend limit.
     * @dev Only owner. Takes effect immediately on next manager execution.
     *      Setting to 0 effectively freezes all manager activity.
     *
     * SECURITY NOTE:
     * Owner can set this to 0 as an emergency freeze mechanism.
     * No separate pause function needed — limit of 0 = frozen.
     */
    function setDailySpendLimit(uint256 _newLimit) external {
        LibDiamond.enforceIsContractOwner();
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        emit DailySpendLimitSet($.dailySpendLimit, _newLimit);
        $.dailySpendLimit = _newLimit;
    }

    /**
     * @notice Update the maximum single position size.
     * @dev Prevents manager from moving entire portfolio in one transaction.
     *      Even if daily limit allows it, single tx is capped here.
     */
    function setMaxPositionSize(uint256 _newSize) external {
        LibDiamond.enforceIsContractOwner();
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        emit MaxPositionSizeSet($.maxPositionSize, _newSize);
        $.maxPositionSize = _newSize;
    }

    /**
     * @notice Add a protocol to the whitelist.
     * @dev Manager can only interact with whitelisted addresses.
     *      Adding Aave pool here allows manager to call deposit/withdraw.
     */
    function addAllowedProtocol(address _protocol) external {
        LibDiamond.enforceIsContractOwner();
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        $.allowedProtocols[_protocol] = true;
        emit ProtocolAllowed(_protocol);
    }

    /**
     * @notice Remove a protocol from the whitelist.
     * @dev Immediately prevents manager from interacting with this address.
     *      Use this if a protocol is compromised or deprecated.
     */
    function removeAllowedProtocol(address _protocol) external {
        LibDiamond.enforceIsContractOwner();
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        $.allowedProtocols[_protocol] = false;
        emit ProtocolRemoved(_protocol);
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    /**
     * @notice Returns current risk parameters.
     * @dev Anyone can call. Used by frontend and monitoring tools.
     */
    function getRiskParams()
        external
        view
        returns (uint256 dailySpendLimit, uint256 maxPositionSize, uint256 dailySpent, uint256 lastResetTimestamp)
    {
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();
        return ($.dailySpendLimit, $.maxPositionSize, $.dailySpent, $.lastResetTimestamp);
    }

    /**
     * @notice Check if a protocol is whitelisted.
     * @param _protocol Address to check
     */
    function isProtocolAllowed(address _protocol) external view returns (bool) {
        return LibRiskParamsStorage.get().allowedProtocols[_protocol];
    }
}
