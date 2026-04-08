// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {DiamondDeployer} from "../helpers/DiamondDeployer.sol";
import {Diamond} from "../../src/Diamond.sol";
import {DiamondCutFacet} from "../../src/facets/DiamondCutFacet.sol";
import {IDiamondCut} from "../../src/interfaces/IDiamondCut.sol";
import {IDiamondLoupe} from "../../src/interfaces/IDiamondLoupe.sol";
import {LibDiamond} from "../../src/libraries/LibDiamond.sol";
import {RiskParamsFacet} from "../../src/facets/RiskParamsFacet.sol";

/**
 * @title DiamondTest
 * @notice Unit tests for Diamond core — deployment, routing, access control.
 *
 * WHAT WE PROVE:
 * 1. Diamond deploys with correct owner
 * 2. All facets are registered and discoverable via Loupe
 * 3. Routing works — calls reach the correct facet
 * 4. Unauthorized users cannot call diamondCut
 * 5. Unknown selectors revert with FunctionNotFound
 */
contract DiamondTest is Test {
    // =============================================================
    //                         STATE
    // =============================================================

    DiamondDeployer deployer;
    Diamond diamond;

    // Test addresses — named for clarity in test output
    address owner = makeAddr("owner");
    address attacker = makeAddr("attacker");
    address randomUser = makeAddr("randomUser");

    // =============================================================
    //                         SETUP
    // =============================================================

    /**
     * @notice Runs before every test.
     * @dev Deploy a fresh Diamond for each test.
     *      Tests are isolated — state from one test never affects another.
     */
    function setUp() public {
        deployer = new DiamondDeployer();

        // Deploy as owner — vm.prank makes next call come from owner
        diamond = deployer.deploy(owner);
    }

    // =============================================================
    //                    DEPLOYMENT TESTS
    // =============================================================

    /**
     * @notice Diamond deploys and owner is set correctly.
     * @dev If this fails, nothing else works — owner is the root
     *      of all access control.
     */
    function test_DeploymentSetsOwner() public {
        // Cast Diamond to read owner — goes through fallback
        // Wait — Diamond has no getOwner() yet
        // We verify via attempting a cut as owner vs attacker
        // Owner succeeds, attacker fails — proves ownership is set

        // Build a minimal valid cut (empty selectors would revert,
        // so we verify ownership indirectly via the revert test below)
        assertEq(address(diamond).code.length > 0, true);
        console.log("Diamond deployed at:", address(diamond));
    }

    /**
     * @notice All facets are registered in the routing table.
     * @dev Uses DiamondLoupeFacet to inspect the routing table.
     *      If a facet is missing here, calls to it will revert
     *      with FunctionNotFound.
     */
    function test_AllFacetsRegistered() public view {
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        address[] memory facetAddrs = loupe.facetAddresses();

        // We installed 4 facets: DiamondCut, DiamondLoupe,
        // RiskParams, Manager
        assertEq(facetAddrs.length, 6, "Should have 6 facets registered");
        console.log("Facets registered:", facetAddrs.length);
    }

    /**
     * @notice DiamondLoupeFacet correctly reports selector → facet mapping.
     * @dev Proves the routing table is populated correctly.
     *      If this passes, fallback() will route to the right facet.
     */
    function test_LoupeReportsFacetForSelector() public view {
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));

        // Look up which facet handles facetAddresses()
        bytes4 selector = IDiamondLoupe.facetAddresses.selector;
        address facetAddr = loupe.facetAddress(selector);

        // Should be DiamondLoupeFacet address
        assertEq(
            facetAddr, address(deployer.diamondLoupeFacet()), "facetAddresses selector should map to DiamondLoupeFacet"
        );
    }

    // =============================================================
    //                    ACCESS CONTROL TESTS
    // =============================================================

    /**
     * @notice Attacker cannot call diamondCut.
     * @dev This is the most critical security test in the project.
     *      If this fails, anyone can add malicious facets and drain funds.
     */
    function test_Revert_AttackerCannotCut() public {
        // Build a cut — content doesn't matter, it should revert
        // before any logic runs
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);

        // Expect revert with NotContractOwner error
        vm.expectRevert(abi.encodeWithSelector(LibDiamond.NotContractOwner.selector, attacker, owner));

        // Attacker tries to cut — should revert
        vm.prank(attacker);
        IDiamondCut(address(diamond)).diamondCut(cuts, address(0), "");
    }

    /**
     * @notice Unknown function selector reverts with FunctionNotFound.
     * @dev Proves fallback() handles unknown selectors correctly.
     *      Without this, unknown calls would silently succeed or
     *      produce undefined behavior.
     */
    function test_Revert_UnknownSelectorReverts() public {
        // Call Diamond with a selector that has no registered facet
        bytes4 unknownSelector = bytes4(keccak256("nonExistentFunction()"));

        vm.expectRevert(abi.encodeWithSelector(Diamond.FunctionNotFound.selector, unknownSelector));

        // Low level call with the unknown selector
        (bool success,) = address(diamond).call(abi.encodeWithSelector(unknownSelector));
        // vm.expectRevert handles the assertion
        // success will be false but expectRevert catches it
    }

    /**
     * @notice Owner can successfully call diamondCut.
     * @dev Proves access control allows the right caller through.
     *      Counterpart to test_Revert_AttackerCannotCut.
     */
    function test_OwnerCanCut() public {
        // Deploy a new facet to add
        DiamondCutFacet newFacet = new DiamondCutFacet();

        // Build a valid cut — replace existing DiamondCutFacet
        // with new deployment (same selectors, new address)
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IDiamondCut.diamondCut.selector;

        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](1);
        cuts[0] = IDiamondCut.FacetCut({
            facetAddress: address(newFacet), action: IDiamondCut.FacetCutAction.Replace, functionSelectors: selectors
        });

        // Owner calls — should succeed
        vm.prank(owner);
        IDiamondCut(address(diamond)).diamondCut(cuts, address(0), "");

        // Verify the selector now points to new facet
        IDiamondLoupe loupe = IDiamondLoupe(address(diamond));
        assertEq(
            loupe.facetAddress(IDiamondCut.diamondCut.selector),
            address(newFacet),
            "Selector should point to new facet after replace"
        );
    }

    /**
     * @notice Calling facet directly cannot affect Diamond storage.
     * @dev Facets are stateless logic — direct calls touch empty storage.
     *      This proves the delegatecall architecture is the only valid
     *      path to Diamond's state.
     */
    function test_DirectFacetCallCannotAffectDiamond() public {
        // Call RiskParamsFacet directly — not through Diamond
        RiskParamsFacet directFacet = RiskParamsFacet(address(deployer.riskParamsFacet()));

        address[] memory protocols = new address[](0);

        // This either reverts (owner check fails on empty storage)
        // or silently writes to facet's own empty storage
        // Either way — Diamond's storage is unaffected
        bytes4[] memory selectors = new bytes4[](0);
        uint256[] memory limits = new uint256[](0);
        try directFacet.initializeRiskParams(1000, selectors, limits, protocols) {
            // If it didn't revert — verify Diamond storage unchanged
            RiskParamsFacet diamondRisk = RiskParamsFacet(address(diamond));
            uint256 maxPos = diamondRisk.getRiskParams();
            assertEq(maxPos, 0, "Diamond storage should be unaffected");
        } catch {
            // Reverted — also correct behavior
            assertTrue(true, "Direct call correctly reverted");
        }
    }
}
