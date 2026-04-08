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

    error MaxPositionSizeExceeded(uint256 attempted, uint256 maximum);
    error ProtocolNotAllowed(address protocol);
    error InvalidAmount();
    error ActionDailyLimitExceeded(bytes4 selector, uint256 attempted, uint256 remaining);

    // =============================================================
    //                         EVENTS
    // =============================================================

    /**
     * @notice Emitted when a manager's action spend is recorded.
     * @param selector      Function selector identifying the action type
     * @param amount        Value of this action
     * @param totalSpent    Running total spent for this action type today
     */
    event ActionSpendRecorded(bytes4 indexed selector, uint256 amount, uint256 totalSpent);

    /**
     * @notice Enforce all risk checks and record the spend.
     * @dev Called by ManagerFacet and facets before every execution.
     *      Checks-Effects-Interactions order is critical:
     *      1. Validate inputs
     *      2. Check protocol whitelist
     *      3. Check global position size cap
     *      4. Reset per-action counter if 24hrs passed
     *      5. Check per-action daily limit
     *      6. Update state (actionDailySpent)
     *      External call happens AFTER this returns in caller.
     *
     * WHY PER-ACTION NOT GLOBAL:
     *      Independent budgets per action type allow complex strategies.
     *      Swap budget exhausted → deposit budget still available.
     *      Manager can chain: swap → deposit proceeds → earn yield.
     *
     * @param _amount    Value of the action
     * @param _protocol  Target protocol address
     * @param _selector  Function selector identifying action type
     */
    function enforceAndRecord(
        uint256 _amount,
        address _protocol,
        bytes4 _selector // which action type
    )
        internal
    {
        if (_amount == 0) revert InvalidAmount();

        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        // Protocol whitelist check
        if (!$.allowedProtocols[_protocol]) revert ProtocolNotAllowed(_protocol);

        // Position size check — still global
        if (_amount > $.maxPositionSize) revert MaxPositionSizeExceeded(_amount, $.maxPositionSize);

        // Per-action daily reset
        if (block.timestamp >= $.actionLastReset[_selector] + 24 hours) {
            $.actionDailySpent[_selector] = 0;
            $.actionLastReset[_selector] = block.timestamp;
        }

        // Per-action daily limit check
        uint256 limit = $.actionDailyLimit[_selector];
        uint256 spent = $.actionDailySpent[_selector];
        uint256 remaining = limit - spent;

        if (_amount > remaining) {
            revert ActionDailyLimitExceeded(_selector, _amount, remaining);
        }

        // Record spend
        $.actionDailySpent[_selector] += _amount;
        emit ActionSpendRecorded(_selector, _amount, $.actionDailySpent[_selector]);
    }
}
