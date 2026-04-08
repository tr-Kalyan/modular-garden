// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IUniswapRouter
 * @notice Minimal interface for Uniswap V3 SwapRouter
 * @dev We only define exactInputSingle - covers the majority of
 *      swap use cases for a portfolio manager.
 *
 * Full interface at:
 * github.com/Uniswap/v3-periphery/blob/main/contracts/interfaces/ISwapRouter.sol
 *
 * V1 SCOPE - exactInputSingle only:
 *      Multi-hop swaps (exactInput) excluded from V1
 *      Single-hop covers BTC↔ETH, ETH↔USDC directly
 *      Mutli-hop required for less liquid pairs - V2 scope
 *
 * Router addresses:
 *      Mainnet:  0xE592427A0AEce92De3Edee1F18E0157C05861564
 *      Sepolia:  0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48
 */
interface IUniswapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    /**
     * @notice Swap exact amount of tokenIn for as much tokenOut as possible
     * @param params Swap parameters
     * @return amountOut Actual amount of tokenOut received
     */
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}
