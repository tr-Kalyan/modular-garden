// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IAavePool
 * @notice Minimal interface for Aave V3 Pool contract
 * @dev We only define the functions we actually call
 *      Full interface at:
 *      github.com/aave/aave-v3-core/blob/master/contracts/interfaces/IPool.sol
 * WHY MINIMAL INTERFACE:
 *      We need only supply() and withdraw()
 *      Minimal interface = faster compilation, cleaner dependencies
 *
 * V1 SCOPE — Deposit and Withdraw only:
 *      Borrow functionality deliberately excluded from V1.
 *      Borrowing creates debt positions requiring additional risk
 *      parameters: maxLeverage, liquidationBuffer, health factor
 *      monitoring. Current risk model is designed for yield strategies,
 *      not leveraged positions.
 *
 * V2 PLANNED:
 *      borrow(asset, amount, interestRateMode, referralCode, onBehalfOf)
 *      repay(asset, amount, interestRateMode, onBehalfOf)
 *      With dedicated BorrowFacet containing leverage controls,
 *      health factor enforcement, and automated deleveraging triggers.
 */
interface IAavePool {
    /**
     * @notice Deposit tokens into Aave and receive aTokens.Aave
     * @param asset         Token to deposit (e.g. USDC, WETH)
     * @param amount        Amount to deposit
     * @param onBehalfOf    Address that receives aTokens
     *                      Set to address(this) - Diamond receives aTokens
     * @param referralCode  Aave referral program (0 = no referral)
     */
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;

    /**
     * @notice Withdraw tokens from Aave by burning aTokens.
     * @param asset    Token to withdraw
     * @param amount   Amount to withdraw (type(uint256).max = withdraw all)
     * @param to       Address that receives the withdrawn tokens
     * @return         Actual amount withdrawn
     */
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}
