// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibRiskParamsStorage, RiskParamsStorage} from "../storage/GardenStorage.sol";

/**
 * @title LibRiskParams
 * @notice Shared enforcement logic for risk parameter checks.
 * @dev Extracted into a library so ManagerFacet can call it directly
 *      without cross-facet external calls. Both RiskParamsFacet and
 *      ManagerFacet import this - one source of truth for enforcement.
 *
 * WHY LIBRARY AND NOT PART OF RiskParamsFacet:
 * ManagerFacet needs to run these checks internally before execution.
 * If the logic lived only in RiskPramsFacet, MangaerFacet would need
 * to call it externally - adding gas overhead and msg.sender complexity.
 * A shared library runs in the same execution context. No external call.
 */
library LibRiskParams {
    // =============================================================
    //                         ERRORS
    // =============================================================

    error DailySpendLimitExceeded(uint256 attempted, uint256 remaining);
    error MaxPositionSizeExceeded(uint256 attempted, uint256 maximum);
    error ProtocolNotAllowed(address protocol);
    error InvalidAmount();

    // =============================================================
    //                         EVENTS
    // =============================================================

    event SpendRecorded(uint256 amount, uint256 totalSpentToday);

    /**
     * @notice Enforce all risk checks and record the spend.
     * @dev Called by ManagerFacet before every execution.
     *      Checks-Effects-Interactions order is critical here:
     *      1. Validate inputs
     *      2. Reset counter if needed
     *      3. Check all limits
     *      4. Update state (dailySpent)
     *      External call happens AFTER this returns in ManagerFacet.
     *
     * @param _amount ETH value of the action
     * @param _protocol Target protocol address
     */
    function enforceAndRecord(uint256 _amount, address _protocol) internal {
        if (_amount == 0) revert InvalidAmount();

        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        // Auto-reset daily counter if 24 hours have passed
        // block.timestamp is acceptable here — 15 second miner
        // manipulation window does not meaningfully affect a 24hr reset
        if (block.timestamp >= $.lastResetTimestamp + 24 hours) {
            $.dailySpent = 0;
            $.lastResetTimestamp = block.timestamp;
        }

        // Check protocol is whitelisted BEFORE any value checks
        // Cheapest revert path for unauthorized protocols
        if (!$.allowedProtocols[_protocol]) revert ProtocolNotAllowed(_protocol);

        // Check single position size cap
        if (_amount > $.maxPositionSize) {
            revert MaxPositionSizeExceeded(_amount, $.maxPositionSize);
        }

        // Check remaining daily budget
        // Subtraction is safe — dailySpent never exceeds dailySpendLimit
        // because we check before adding
        uint256 remaining = $.dailySpendLimit - $.dailySpent;
        if (_amount > remaining) {
            revert DailySpendLimitExceeded(_amount, remaining);
        }

        // EFFECTS — update state before any external call
        $.dailySpent += _amount;
        emit SpendRecorded(_amount, $.dailySpent);
    }
}
