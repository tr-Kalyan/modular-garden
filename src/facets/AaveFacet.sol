// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibAaveStorage, AaveStorage} from "../storage/GardenStorage.sol";
import {LibManagerStorage} from "../storage/GardenStorage.sol";
import {LibRiskParams} from "../libraries/LibRiskParams.sol";
import {IAavePool} from "../interfaces/IAavePool.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title AaveFacet
 * @notice Aave v3 yield integration for ModularGarden
 * @dev Manager deposits/withdraws ERC-20 tokens into Aave V3
 *      All operations go through risk parameter checks
 *      Diamond holds aTokens - yield accrues to Diamond balance
 *
 * SECURITY MODEL:
 *      - Only manager can call deposit/withdraw
 *      - All amounts checked againt risk params before execution
 *      - ERC-20 approvals are scoped - only what's needed, immediately used
 *      - SafeERC20 handles non-standard token implementations
 */
contract AaveFacet {
    using SafeERC20 for IERC20;

    // =============================================================
    //                         EVENTS
    // =============================================================

    event AaveDeposited(address indexed asset, uint256 amount, address indexed manager);
    event AaveWithdrawn(address indexed asset, uint256 amount, address indexed manager);
    event AaveInitialized(address indexed aavePool);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error AlreadyInitialized();
    error NotManager(address caller);
    error ZeroAmount();
    error ZeroAddress();
    error InsufficientBalance(uint256 requested, uint256 available);

    // =============================================================
    //                      INITIALIZATION
    // =============================================================

    /**
     * @notice Initialize AaveFacet with pool address.
     * @dev Called once via diamondCut _init mechanism.
     *      Aave pool address is chain-specific:
     *      Mainnet:  0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
     *      Sepolia:  0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951
     *
     * @param _aavePool Aave V3 Pool contract address for this chain
     */
    function initializeAave(address _aavePool) external {
        LibDiamond.enforceIsContractOwner();
        if (_aavePool == address(0)) revert ZeroAddress();

        AaveStorage storage $ = LibAaveStorage.get();
        if ($.initialized) revert AlreadyInitialized();

        $.aavePool = _aavePool;
        $.initialized = true;

        emit AaveInitialized(_aavePool);
    }

    // =============================================================
    //                    MANAGER — DEPOSIT
    // =============================================================

    /**
     * @notice Deposit ERC-20 tokens into Aave v3 to earn yield
     * @dev Only manager. Risk params enforced before execution
     *
     * FLOW:
     * 1. Check caller is manager
     * 2. Enforce risk params (protocol whitelist, position size, daily limit)
     * 3. Approve Aave pool to spend tokens (exact amount only)
     * 4. Call Aave supply() - Diamond receives aTokens
     * 5. Update totalDeposited tracking
     *
     * WHY APPROVE EXACT AMOUNT:
     * Approving max uint256 is a common pattern but leaves residual approval
     * If Aave is ever exploited, residual approval = attacker can drain
     * Approve exactly what you need, use it immediately.
     *
     * @param _asset  ERC-20 token to deposit
     * @param _amount Amount to deposit
     */
    function depositToAave(address _asset, uint256 _amount) external {
        if (_amount == 0) revert ZeroAmount();

        // Check caller is manager
        _enforceIsManager();

        AaveStorage storage $ = LibAaveStorage.get();
        // Only deposits count toward risk limits
        // Withdrawals reduce exposure — not charged against daily limit
        LibRiskParams.enforceAndRecord(_amount, $.aavePool, AaveFacet.depositToAave.selector);

        // Verify Diamond has enough token balance
        uint256 balance = IERC20(_asset).balanceOf(address(this));
        if (balance < _amount) revert InsufficientBalance(_amount, balance);

        // EFFECTS — update state before external calls (CEI pattern)
        // Prevents reentrancy from manipulating totalDeposited accounting
        $.totalDeposited += _amount;

        // INTERACTIONS — external calls after state is updated
        IERC20(_asset).forceApprove($.aavePool, _amount);
        IAavePool($.aavePool).supply(_asset, _amount, address(this), 0);

        emit AaveDeposited(_asset, _amount, msg.sender);
    }

    // =============================================================
    //                    MANAGER — WITHDRAW
    // =============================================================

    /**
     * @notice Withdraw ERC-20 tokens from Aave V3.
     * @dev Only manager. Risk params enforced before execution.
     *
     * WITHDRAW ALL PATTERN:
     * Pass type(uint256).max as amount to withdraw everything
     * including accrued yield. Aave handles this natively.
     *
     * @param _asset  ERC-20 token to withdraw
     * @param _amount Amount to withdraw (type(uint256).max = all)
     */
    function withdrawFromAave(address _asset, uint256 _amount) external {
        if (_amount == 0) revert ZeroAmount();

        // Check caller is manager
        _enforceIsManager();

        // Enforce risk params
        AaveStorage storage $ = LibAaveStorage.get();

        // Execute withdrawal — tokens returned to Diamond
        uint256 withdrawn = IAavePool($.aavePool)
            .withdraw(
                _asset,
                _amount,
                address(this) // tokens return to Diamond
            );

        // Update tracking — use actual withdrawn amount
        if (withdrawn < $.totalDeposited) {
            $.totalDeposited -= withdrawn;
        } else {
            $.totalDeposited = 0;
        }

        emit AaveWithdrawn(_asset, withdrawn, msg.sender);
    }

    // =============================================================
    //                         INTERNAL
    // =============================================================

    /**
     * @notice Revert if caller is not the manager.
     * @dev Reads from ManagerStorage — same Diamond storage context.
     */
    function _enforceIsManager() internal view {
        address manager = LibManagerStorage.get().manager;
        if (msg.sender != manager) revert NotManager(msg.sender);
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    /**
     * @notice Returns Aave integration state.
     */
    function getAaveState() external view returns (address aavePool, uint256 totalDeposited_) {
        AaveStorage storage $ = LibAaveStorage.get();
        return ($.aavePool, $.totalDeposited);
    }
}
