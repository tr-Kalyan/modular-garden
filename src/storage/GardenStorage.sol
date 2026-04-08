// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title GardenStorage
 * @notice ERC-7201 namespaced storage for all ModularGarden facets.
 *
 * WHY ONE FILE:
 * All business data storage lives here. One place for auditors to review.
 * Easy to verify no collision between facets. Easy to track what data
 * each facet owns.
 *
 * WHY NOT LIBDIAMOND:
 * LibDiamond owns routing infrastructure (selector → facet mapping)
 * GardenStorage owns business data (limits, balances, manager addresses).
 * Separate concerns - upgraing one never touches the other.
 *
 * ERC-7201 FORMULA:
 *  slot = keccak256(abi.encode(uint256(keccak256(bytes(namespace))) -1)) & ~bytes32(uint256(0xff))
 * The & ~0xff clears the last byte — reserves 256 consecutive slots
 * for each namespace so structs can grow without collision.
 */

// =============================================================
//                    RISK PARAMS STORAGE
// =============================================================

/**
 * @notice Storage for RiskParamsFacet.
 * @dev Defines what a manager is allowed to do.
 *      Owner sets these. Manager cannot exceed them.
 *
 * actionDailyLimit:
 *      Per-action daily spend limit
 *      Keyed by function selector
 *      e.g. depositToAave.selector → 6000 USDC per day
 *           swap.selector          → 5000 USDC per day
 *      Each action type has an independent budget
 *      Exhausting swap budget does not block deposit budget
 *
 * actionDailySpent:
 *      Running total spent per action type today.
 *      Resets independently per action when 24hrs pass.
 *
 * actionLastReset:
 *      Timestamp of last reset per action type.
 *      Each action resets independently — swap and deposit
 *      do not share a reset window.
 * allowedProtocols:
 *      Whitelist of contract addresses a manager can intereact with.
 *      e.g. Aave pool, Uniswap router.
 *      Manager cannot call any address not in the mapping
 *
 * maxPositionSize:
 *      Maximum ETH value of any single transaction.
 *      Prevents manager from moving everything in one call.
 *
 * initialized:
 *      Guards against re-initialization attack
 *      Set to true after first init. Can never be set to false.
 *
 * WHY PER-ACTION LIMITS OVER GLOBAL DAILY LIMIT:
 *      A global daily limit blocks legitimate multi-step strategies.
 *      Example: manager swaps 5000 USDC → ETH, then deposits
 *      proceeds into Aave. With global limit, swap consumes budget
 *      and blocks the deposit. With per-action limits, each step
 *      has its own independent budget — complex strategies work
 *      without one action type starving another.
 *
 *      This mirrors Enzyme Finance's policy framework applied
 *      at the action-type level.
 */

struct RiskParamsStorage {
    // Per-action limits — selector → daily limit
    mapping(bytes4 => uint256) actionDailyLimit;
    mapping(bytes4 => uint256) actionDailySpent;
    mapping(bytes4 => uint256) actionLastReset;

    // Global position cap
    uint256 maxPositionSize;

    // Protocol whitelist — still applies
    mapping(address => bool) allowedProtocols;

    bool initialized;
}

// =============================================================
//                    MANAGER STORAGE
// =============================================================

/**
 * @notice Storage for ManagerFacet.
 * @dev Tracks who is allowed to execute strategies.
 *
 * manager:
 *      The single address allowed to call execute functions.
 *      Can be human, a multisig, or an AI agent's key.
 *      Owner sets this. Owner can revoke it at any time.
 *
 * WHY SINGLE MANAGER (not a mapping):
 *      Simplicity for v1. A mapping of managers adds complexity
 *      to the risk accounting - which manager spent what today ?
 *      single manager = clean dialy limit tracking.
 *      Multi-manager is a documented future upgrade.
 */
struct ManagerStorage {
    address manager;
    bool initialized;
}

// =============================================================
//                    AAVE STORAGE
// =============================================================

/**
 * @notice Storage for AaveFacet.
 * @dev Tracks Aave integration state.
 *
 * aavePool:
 *      Address of Aave V3 Pool contract on the deployed chain.
 *      Set during initialization. Can be updated via diamondCut
 *      if Aave deploys a new pool version.
 *
 * totalDeposited:
 *      Running total of assets deposited into Aave.
 *      Used for yield calculation and position tracking.
 */
struct AaveStorage {
    address aavePool;
    uint256 totalDeposited;
    bool initialized;
}

// =============================================================
//                    SWAP STORAGE
// =============================================================

/**
 * @notice Storage for SwapFacet.
 * @dev Tracks Uniswap integration state.
 *
 * swapRouter:
 *      Address of Uniswap V3 SwapRouter on the deployed chain.
 *
 * defaultSlippage:
 *      Default max slippage in basis points (e.g. 50 = 0.5%).
 *      Manager cannot override this — it's enforced at the facet level.
 *      Owner sets it. Protects against sandwich attacks.
 */
struct SwapStorage {
    address swapRouter;
    uint24 defaultSlippage;
    bool initialized;
}

// =============================================================
//                    VALIDATOR STORAGE
// =============================================================

/**
 * @notice Storage for ECDSAValidatorFacet.
 * @dev Stores the owner address that signatures are verified against.
 *
 * owner:
 *      The address whose private key signs UserOperations.
 *      Set during initialization.
 *      Can be updated via setOwner() - key rotaion without redeployment.
 *
 * WHY SEPERATE FROM LibDiamond.contractOwner:
 *      LibDiamond.contractOwner controls Diamond upgrades (diamondCut).
 *      Should be a multisig or timelock — used rarely, high security.
 *
 *      ValidatorStorage.owner controls UserOperation signing.
 *      Used for every strategy execution — can be a standard EOA.
 *      Can be rotated via setOwner() without touching diamondCut.
 *
 *      Compromising the signing key does not grant upgrade access.
 *      Compromising the Diamond owner does not grant execution access.
 *      Two independent threat surfaces.
 */
struct ValidatorStorage {
    address owner;
    bool initialized;
}

// =============================================================
//                    STORAGE LIBRARIES
// =============================================================

/**
 * @title LibRiskParamsStorage
 * @notice ERC-7201 storage accessor for RiskParamsStorage
 * @dev Any contract that imports this can call LibRiskParamsStorage.get()
 *      to read or write RiskParams data in Diamond's storage context.
 */
library LibRiskParamsStorage {
    /// @dev keccak256(abi.encode(uint256(keccak256("modular.garden.riskparams)) -1)) & ~bytes32(uint256(0xff))
    bytes32 constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256(bytes("modular.garden.riskparams"))) - 1)) & ~bytes32(uint256(0xff));

    function get() internal pure returns (RiskParamsStorage storage $) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            $.slot := position
        }
    }
}

/**
 * @title LibManagerStorage
 * @notice ERC-7201 storage accessor for ManagerStorage.
 */
library LibManagerStorage {
    /// @dev keccak256(abi.encode(uint256(keccak256("modular.garden.manager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256(bytes("modular.garden.manager"))) - 1)) & ~bytes32(uint256(0xff));

    function get() internal pure returns (ManagerStorage storage $) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            $.slot := position
        }
    }
}

/**
 * @title LibAaveStorage
 * @notice ERC-7201 storage accessor for AaveStorage.
 */
library LibAaveStorage {
    /// @dev keccak256(abi.encode(uint256(keccak256("modular.garden.aave")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256(bytes("modular.garden.aave"))) - 1)) & ~bytes32(uint256(0xff));

    function get() internal pure returns (AaveStorage storage $) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            $.slot := position
        }
    }
}

/**
 * @title LibSwapStorage
 * @notice ERC-7201 storage accessor for SwapStorage.
 */
library LibSwapStorage {
    /// @dev keccak256(abi.encode(uint256(keccak256("modular.garden.swap")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256(bytes("modular.garden.swap"))) - 1)) & ~bytes32(uint256(0xff));

    function get() internal pure returns (SwapStorage storage $) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            $.slot := position
        }
    }
}

library LibValidatorStorage {
    /// @dev keccak256(abi.encode(uint256(keccak256("modular.garden.validator")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256(bytes("modular.garden.validator"))) - 1)) & ~bytes32(uint256(0xff));

    function get() internal pure returns (ValidatorStorage storage $) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            $.slot := position
        }
    }
}
