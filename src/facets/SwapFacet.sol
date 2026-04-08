// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibSwapStorage, SwapStorage} from "../storage/GardenStorage.sol";
import {LibManagerStorage} from "../storage/GardenStorage.sol";
import {LibRiskParams} from "../libraries/LibRiskParams.sol";
import {IUniswapRouter} from "../interfaces/IUniswapRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title SwapFacet
 * @notice Uniswap V3 token swap integration for ModularGarden
 * @dev Manager swaps ERC-20 tokens via Uniswap V3 exactInputSingle
 *      Slippage protection enforced at facet level - manager cannot override
 *
 * SECURITY MODEL:
 *      - Only manager can call swap
 *      - Risk params enforced before execution (CEI pattern)
 *      - defaultSlippage enforced - manager cannot pass arbitray minimum
 *      - Exact approval - no residual allowance after swap
 *
 * DESGIN DECISION - Why enforce slippage at facet level:
 *      If manager could pass arbitrary amountOutMinimum, they could
 *      set it to 0 - accepting any output including sandwhich attack result
 *      Owner sets defaultSlippage in basis points
 *      Facet computes amountOutMinimum from it
 *      Manager cannot bypass this
 *
 * DESIGN CHOICE:
 *      Multi-hop swaps excluded. Single-hop covers BTC↔ETH, ETH↔USDC
 *
 * Multi-hop needed for illiquid pairs — documented as V2.
 *
 * V2 PLANNED:
 *      exactInput() — multi-hop swaps via encoded path
 *      Required for: WBTC→USDC (no direct pool, routes via ETH)
 */
contract SwapFacet {
    using SafeERC20 for IERC20;

    // Basis points denominator
    uint256 constant BPS = 10000;

    // =============================================================
    //                         EVENTS
    // =============================================================

    event SwapExecuted(
        address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut, address indexed manager
    );
    event SwapInitialized(address indexed swapRouter, uint24 defaultSlippage);

    // =============================================================
    //                         ERRORS
    // =============================================================

    error AlreadyInitialized();
    error NotManager(address caller);
    error ZeroAmount();
    error ZeroAddress();
    error InsufficientBalance(uint256 requested, uint256 available);
    error SlippageTooHigh(uint24 slippage, uint24 maximum);

    // =============================================================
    //                      INITIALIZATION
    // =============================================================

    /**
     * @notice Initialize SwapFacet with router address and slippage
     * @dev Called once via diamondCut _init mechanism
     *
     * @param _swapRouter       Uniswap V3 SwapRouter address
     * @param _defaultSlippage  Max slippage in basis points (e.g. 50 = 0.5%)
     */
    function initializeSwap(address _swapRouter, uint24 _defaultSlippage) external {
        LibDiamond.enforceIsContractOwner();
        if (_swapRouter == address(0)) revert ZeroAddress();

        // Cap slippage at 10% - anything higher is dangerous
        if (_defaultSlippage > 1000) revert SlippageTooHigh(_defaultSlippage, 1000);

        SwapStorage storage $ = LibSwapStorage.get();
        if ($.initialized) revert AlreadyInitialized();

        $.swapRouter = _swapRouter;
        $.defaultSlippage = _defaultSlippage;
        $.initialized = true;

        emit SwapInitialized(_swapRouter, _defaultSlippage);
    }

    // =============================================================
    //                    MANAGER — SWAP
    // =============================================================

    /**
     * @notice Swap exact amount of tokenIn for tokenOut via Uniswap V3
     * @dev Only manager. Risk params enforced. Slippage protected
     *
     * FLOW:
     * 1. Check caller is manager
     * 2. Enforce risk params - amount vs daily limit, protocol whitelist
     * 3. Check Diamond has sufficient tokenIn balance
     * 4. EFFECTS - no state to update before swap (unlike deposit)
     * 5 Approve exact amountIn to router
     * 6. Execute swap - Dimaond received tokenOut
     * 7. Clear residual approval (safety)
     *
     * WHY amountOutMinimum IS COMPUTED NOT PASSED:
     *      Manager cannot set their own minimum output
     *      Owner's defaultSlippage setting is enforced
     *      Prevents manager from accepting sandwich attack losses.
     * @param _tokenIn      Token to sell
     * @param _tokenOut     Token to buy
     * @param _fee          Uniswap pool fee tier (500, 3000, or 10000)
     * @param _amountIn     Exact amount of tokenIn to sell
     */
    function swap(address _tokenIn, address _tokenOut, uint24 _fee, uint256 _amountIn) external {
        if (_amountIn == 0) revert ZeroAmount();

        _enforceIsManager();

        SwapStorage storage $ = LibSwapStorage.get();

        // Enforce risk params — tracks against swap selector
        LibRiskParams.enforceAndRecord(_amountIn, $.swapRouter, SwapFacet.swap.selector);

        // Check balance
        uint256 balance = IERC20(_tokenIn).balanceOf(address(this));
        if (balance < _amountIn) revert InsufficientBalance(_amountIn, balance);

        // Compute minimum output from owner-set slippage
        // amountOutMinimum = amountIn * (1 - slippage/BPS)
        // Note: this is a simplified approximation
        // Production would use an oracle for accurate minimum
        uint256 amountOutMinimum = _amountIn * (BPS - $.defaultSlippage) / BPS;
        // Approve exact amount
        IERC20(_tokenIn).forceApprove($.swapRouter, _amountIn);

        // Execute swap — Diamond receives tokenOut
        uint256 amountOut = IUniswapRouter($.swapRouter)
            .exactInputSingle(
                IUniswapRouter.ExactInputSingleParams({
                    tokenIn: _tokenIn,
                    tokenOut: _tokenOut,
                    fee: _fee,
                    recipient: address(this),
                    amountIn: _amountIn,
                    amountOutMinimum: amountOutMinimum,
                    sqrtPriceLimitX96: 0
                })
            );

        // Clear residual approval — safety measure
        IERC20(_tokenIn).forceApprove($.swapRouter, 0);

        emit SwapExecuted(_tokenIn, _tokenOut, _amountIn, amountOut, msg.sender);
    }

    // =============================================================
    //                    OWNER — UPDATE SLIPPAGE
    // =============================================================

    /**
     * @notice Update default slippage tolerance.
     * @dev Only owner. Takes effect on next swap.
     *      Lower = tighter protection but more failed swaps in volatile markets.
     *      Higher = more swaps succeed but more sandwich attack exposure.
     *
     * @param _newSlippage New slippage in basis points
     */
    function setDefaultSlippage(uint24 _newSlippage) external {
        LibDiamond.enforceIsContractOwner();
        if (_newSlippage > 1000) revert SlippageTooHigh(_newSlippage, 1000);

        SwapStorage storage $ = LibSwapStorage.get();
        $.defaultSlippage = _newSlippage;
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    function getSwapState() external view returns (address swapRouter, uint24 defaultSlippage) {
        SwapStorage storage $ = LibSwapStorage.get();
        return ($.swapRouter, $.defaultSlippage);
    }

    // =============================================================
    //                         INTERNAL
    // =============================================================

    function _enforceIsManager() internal view {
        address manager = LibManagerStorage.get().manager;
        if (msg.sender != manager) revert NotManager(msg.sender);
    }
}
