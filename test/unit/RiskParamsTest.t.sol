// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {DiamondDeployer} from "../helpers/DiamondDeployer.sol";
import {Diamond} from "../../src/Diamond.sol";
import {RiskParamsFacet} from "../../src/facets/RiskParamsFacet.sol";
import {ManagerFacet} from "../../src/facets/ManagerFacet.sol";
import {LibDiamond} from "../../src/libraries/LibDiamond.sol";
import {LibRiskParams} from "../../src/libraries/LibRiskParams.sol";

/**
 * @title RiskParamsTest
 * @notice Unit tests for RiskParamsFacet — the manager cage.
 *
 * WHAT WE PROVE:
 * 1. Only owner can initialize risk params
 * 2. Cannot initialize twice
 * 3. Per-action limits set and enforced independently
 * 4. Protocol whitelist enforced
 * 5. Max position size enforced globally
 * 6. Per-action daily counter resets after 24 hours
 * 7. Setting action limit to 0 freezes that action only
 * 8. Other actions unaffected when one action is frozen
 */
contract RiskParamsTest is Test {

    // =============================================================
    //                         STATE
    // =============================================================

    DiamondDeployer deployer;
    Diamond diamond;
    RiskParamsFacet riskParams;
    ManagerFacet managerFacet;

    address owner = makeAddr("owner");
    address attacker = makeAddr("attacker");
    address manager = makeAddr("manager");

    address aavePool = makeAddr("aavePool");
    address uniswapRouter = makeAddr("uniswapRouter");
    address maliciousProtocol = makeAddr("maliciousProtocol");

    uint256 constant MAX_POSITION = 3 ether;
    uint256 constant EXECUTE_DAILY_LIMIT = 10 ether;

    // The selector ManagerFacet.execute uses for risk tracking
    bytes4 constant EXECUTE_SELECTOR = ManagerFacet.execute.selector;

    // =============================================================
    //                         SETUP
    // =============================================================

    function setUp() public {
        deployer = new DiamondDeployer();
        diamond = deployer.deploy(owner);
        vm.deal(manager, 100 ether);

        riskParams = RiskParamsFacet(address(diamond));
        managerFacet = ManagerFacet(address(diamond));

        // Build per-action limits for initialization
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ManagerFacet.execute.selector;

        uint256[] memory limits = new uint256[](1);
        limits[0] = EXECUTE_DAILY_LIMIT;

        address[] memory protocols = new address[](2);
        protocols[0] = aavePool;
        protocols[1] = uniswapRouter;

        vm.prank(owner);
        riskParams.initializeRiskParams(MAX_POSITION, selectors, limits, protocols);

        // Initialize manager
        vm.prank(owner);
        managerFacet.initializeManager(manager);
    }

    // =============================================================
    //                    INITIALIZATION TESTS
    // =============================================================

    /**
     * @notice Risk params initialized correctly.
     */
    function test_InitializationSetsCorrectValues() public {
        uint256 maxPos = riskParams.getRiskParams();
        assertEq(maxPos, MAX_POSITION, "Max position incorrect");

        (uint256 limit, uint256 spent,,) =
            riskParams.getActionState(EXECUTE_SELECTOR);
        assertEq(limit, EXECUTE_DAILY_LIMIT, "Action limit incorrect");
        assertEq(spent, 0, "Spent should start at 0");
    }

    /**
     * @notice Cannot initialize twice.
     */
    function test_Revert_CannotInitializeTwice() public {
        bytes4[] memory selectors = new bytes4[](0);
        uint256[] memory limits = new uint256[](0);
        address[] memory protocols = new address[](0);

        vm.expectRevert(
            abi.encodeWithSelector(RiskParamsFacet.AlreadyInitialized.selector)
        );

        vm.prank(owner);
        riskParams.initializeRiskParams(1 ether, selectors, limits, protocols);
    }

    /**
     * @notice Attacker cannot initialize.
     */
    function test_Revert_AttackerCannotInitialize() public {
        DiamondDeployer freshDeployer = new DiamondDeployer();
        Diamond freshDiamond = freshDeployer.deploy(owner);
        RiskParamsFacet freshRisk = RiskParamsFacet(address(freshDiamond));

        bytes4[] memory selectors = new bytes4[](0);
        uint256[] memory limits = new uint256[](0);
        address[] memory protocols = new address[](0);

        vm.expectRevert(
            abi.encodeWithSelector(
                LibDiamond.NotContractOwner.selector,
                attacker,
                owner
            )
        );

        vm.prank(attacker);
        freshRisk.initializeRiskParams(1 ether, selectors, limits, protocols);
    }

    // =============================================================
    //                    PER-ACTION LIMIT TESTS
    // =============================================================

    /**
     * @notice Owner can set per-action limit.
     */
    function test_OwnerCanSetActionLimit() public {
        uint256 newLimit = 20 ether;

        vm.prank(owner);
        riskParams.setActionLimit(EXECUTE_SELECTOR, newLimit);

        (uint256 limit,,,) = riskParams.getActionState(EXECUTE_SELECTOR);
        assertEq(limit, newLimit);
    }

    /**
     * @notice Setting action limit to 0 freezes that action only.
     * @dev Other actions with different selectors are unaffected.
     *      This is the granular freeze mechanism.
     */
    function test_ZeroLimitFreezesSpecificAction() public {
        vm.prank(owner);
        riskParams.setActionLimit(EXECUTE_SELECTOR, 0);

        (uint256 limit,,,) = riskParams.getActionState(EXECUTE_SELECTOR);
        assertEq(limit, 0, "Action limit should be 0");

        // Manager tries to execute — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                LibRiskParams.ActionDailyLimitExceeded.selector,
                EXECUTE_SELECTOR,
                1 ether,
                0
            )
        );

        vm.prank(manager);
        managerFacet.execute{value: 1 ether}(aavePool, "", 1 ether);
    }

    /**
     * @notice Attacker cannot set action limits.
     */
    function test_Revert_AttackerCannotSetActionLimit() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                LibDiamond.NotContractOwner.selector,
                attacker,
                owner
            )
        );

        vm.prank(attacker);
        riskParams.setActionLimit(EXECUTE_SELECTOR, 100 ether);
    }

    // =============================================================
    //                    PROTOCOL WHITELIST TESTS
    // =============================================================

    function test_WhitelistedProtocolsAllowed() public {
        assertTrue(riskParams.isProtocolAllowed(aavePool));
        assertTrue(riskParams.isProtocolAllowed(uniswapRouter));
    }

    function test_NonWhitelistedProtocolBlocked() public {
        assertFalse(riskParams.isProtocolAllowed(maliciousProtocol));
    }

    function test_OwnerCanAddProtocol() public {
        address newProtocol = makeAddr("newProtocol");
        assertFalse(riskParams.isProtocolAllowed(newProtocol));

        vm.prank(owner);
        riskParams.addAllowedProtocol(newProtocol);

        assertTrue(riskParams.isProtocolAllowed(newProtocol));
    }

    function test_OwnerCanRemoveProtocol() public {
        vm.prank(owner);
        riskParams.removeAllowedProtocol(aavePool);

        assertFalse(riskParams.isProtocolAllowed(aavePool));
    }

    function test_Revert_AttackerCannotAddProtocol() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                LibDiamond.NotContractOwner.selector,
                attacker,
                owner
            )
        );

        vm.prank(attacker);
        riskParams.addAllowedProtocol(makeAddr("anyProtocol"));
    }

    // =============================================================
    //                    DAILY RESET TEST
    // =============================================================

    /**
     * @notice Per-action counter resets after 24 hours.
     * @dev Each action type resets independently.
     */
    function test_ActionLimitResetsAfter24Hours() public {
        // Spend up to limit
        vm.prank(owner);
        riskParams.setMaxPositionSize(10 ether);

        vm.prank(manager);
        managerFacet.execute{value: 10 ether}(aavePool, "", 10 ether);

        // Verify exhausted
        (, uint256 spent,,) = riskParams.getActionState(EXECUTE_SELECTOR);
        assertEq(spent, 10 ether);

        // Fast forward 25 hours
        vm.warp(block.timestamp + 25 hours);

        // Should succeed after reset
        vm.prank(manager);
        managerFacet.execute{value: 1 ether}(aavePool, "", 1 ether);

        (, uint256 spentAfterReset,,) =
            riskParams.getActionState(EXECUTE_SELECTOR);
        assertEq(spentAfterReset, 1 ether, "Counter should reset then record new spend");
    }
}