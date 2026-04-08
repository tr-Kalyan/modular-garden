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
 * - LibRiskParams.enforceAndRecord() called by facets before every execution
 * - Manager never touches risk accounting directly
 * - Daily limits reset automatically per action type — no manual reset needed
 *
 * PER-ACTION LIMIT DESIGN:
 * Each function selector has an independent daily budget.
 * Exhausting swap budget does not block deposit budget.
 * Manager can chain: swap → deposit proceeds → earn yield.
 * This mirrors Enzyme Finance's policy framework at the action level.
 *
 * DESIGN DECISION — Why timestamp-based reset:
 * Block-based resets are predictable and gameable.
 * A manager can time transactions to straddle block boundaries
 * and effectively double their limit. Timestamp-based resets
 * tied to 24-hour windows are harder to game.
 */
contract RiskParamsFacet {
    // =============================================================
    //                         EVENTS
    // =============================================================

    event ActionLimitSet(bytes4 indexed selector, uint256 oldLimit, uint256 newLimit);
    event MaxPositionSizeSet(uint256 oldSize, uint256 newSize);
    event ProtocolAllowed(address indexed protocol);
    event ProtocolRemoved(address indexed protocol);
    event RiskParamsInitialized(uint256 maxPositionSize);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error AlreadyInitialized();
    error ArrayLengthMismatch();

    // =============================================================
    //                      INITIALIZATION
    // =============================================================

    /**
     * @notice Initialize RiskParams storage with default values.
     * @dev Called once via diamondCut _init mechanism.
     *      Never callable again — initialized flag prevents it.
     *
     * WHY NOT A CONSTRUCTOR:
     *      This runs via delegatecall from the Diamond after the facet
     *      is registered. Constructors don't run in proxy context.
     *      This is the proxy-safe alternative.
     *
     * @param _maxPositionSize      Global per-transaction cap
     * @param _selectors            Action selectors to set limits for
     * @param _limits               Corresponding daily limits per selector
     * @param _allowedProtocols     Initial protocol whitelist
     */
    function initializeRiskParams(
        uint256 _maxPositionSize,
        bytes4[] calldata _selectors,
        uint256[] calldata _limits,
        address[] calldata _allowedProtocols
    ) external {
        LibDiamond.enforceIsContractOwner();

        // Validate arrays match
        if (_selectors.length != _limits.length) revert ArrayLengthMismatch();

        RiskParamsStorage storage $ = LibRiskParamsStorage.get();
        if ($.initialized) revert AlreadyInitialized();

        $.maxPositionSize = _maxPositionSize;
        $.initialized = true;

        // Set per-action limits
        for (uint256 i; i < _selectors.length;) {
            $.actionDailyLimit[_selectors[i]] = _limits[i];
            emit ActionLimitSet(_selectors[i], 0, _limits[i]);
            unchecked {
                ++i;
            }
        }

        // Whitelist protocols
        for (uint256 i; i < _allowedProtocols.length;) {
            $.allowedProtocols[_allowedProtocols[i]] = true;
            emit ProtocolAllowed(_allowedProtocols[i]);
            unchecked {
                ++i;
            }
        }

        emit RiskParamsInitialized(_maxPositionSize);
    }

    // =============================================================
    //                    OWNER — SET PARAMS
    // =============================================================

    /**
     * @notice Set daily limit for a specific action selector.
     * @dev Owner sets independent budget per action type.
     *      Setting to 0 freezes that specific action type.
     *      Other action types are unaffected.
     *
     * EXAMPLE:
     *      setActionLimit(AaveFacet.depositToAave.selector, 6000e6)
     *      setActionLimit(SwapFacet.swap.selector, 5000e6)
     *
     * EMERGENCY FREEZE:
     *      setActionLimit(SwapFacet.swap.selector, 0)
     *      → freezes swaps only, deposits still work
     *
     * @param _selector   Function selector to set limit for
     * @param _newLimit   New daily limit (0 = freeze this action)
     */
    function setActionLimit(bytes4 _selector, uint256 _newLimit) external {
        LibDiamond.enforceIsContractOwner();
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();

        uint256 oldLimit = $.actionDailyLimit[_selector];
        $.actionDailyLimit[_selector] = _newLimit;

        emit ActionLimitSet(_selector, oldLimit, _newLimit);
    }

    /**
     * @notice Update the maximum single position size.
     * @dev Global cap — applies to all action types.
     *      Prevents manager from moving everything in one call
     *      regardless of which action type it is.
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
     *      Use if protocol is compromised or deprecated.
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
     * @notice Returns global risk parameters.
     */
    function getRiskParams() external view returns (uint256 maxPositionSize) {
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();
        return $.maxPositionSize;
    }

    /**
     * @notice Returns per-action limit and current spend.
     * @param _selector Function selector to query
     */
    function getActionState(bytes4 _selector)
        external
        view
        returns (uint256 dailyLimit, uint256 dailySpent, uint256 lastReset, uint256 remaining)
    {
        RiskParamsStorage storage $ = LibRiskParamsStorage.get();
        dailyLimit = $.actionDailyLimit[_selector];
        dailySpent = $.actionDailySpent[_selector];
        lastReset = $.actionLastReset[_selector];
        remaining = dailyLimit > dailySpent ? dailyLimit - dailySpent : 0;
    }

    /**
     * @notice Check if a protocol is whitelisted.
     */
    function isProtocolAllowed(address _protocol) external view returns (bool) {
        return LibRiskParamsStorage.get().allowedProtocols[_protocol];
    }
}
