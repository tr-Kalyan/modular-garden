// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibDiamond} from "./libraries/LibDiamond.sol";
import {IDiamondCut} from "./interfaces/IDiamondCut.sol";

/**
 * @title ModularGarden Diamond Proxy
 * @notice The core proxy contract. Every user gets one instance deployed.
 *         by GardenFactory. This contract holds all funds and state.
 *         All function calls are routed to the appropriate facet via fallback().
 *
 * WHAT LIVES HERE:
 *      - The routing table (via LibDiamond stroage)
 *      - All business data (via ERC-7201 storage in each facet's namespace)
 *      - The ETH balance
 *
 * WHAT DOES NOT LIVE HERE:
 *      - Business logic (that's in facets)
 *      - Upgrade logic (that's in DiamondCutFacet)
 *      - Introspection logic (that's in DiamondLoupeFacet)
 */

contract Diamond {
    error FunctionNotFound(bytes4 selector);
    /**
     * @notice Deploy a new Garden Diamond.
     * @param _contractOwner The user who owns this Garden.
     *                       Only they can call the diamondCut to add/upgrade facets.
     * @param _diamondCutFacet Address of the DiamondCutFacet contract.
     *                         We register it immediately so the owner can
     *                         add more facets after deployment.
     *
     * WHY DIAMONDCUTFACET IN CONSTRUCTOR:
     *      - The Diamond starts with zero facets - nothing is registered.
     *      - But to add facets you need diamondCut().
     *      - But diamondCut() is in DiamondCutFacet.
     *      - Chicken and egg problem.
     *      - Solution: register DiamondCutFacet directly in the constructor,
     *      - bypassing the normal diamondCut flow. After this, everything
     *      - else is added through the proper diamondCut mechanism.
     */

    constructor(address _contractOwner, address _diamondCutFacet) payable {
        // Set the owner first - enforceIsContractOwner checks this
        LibDiamond.setContractOwner(_contractOwner);

        // Register DiamondCutFacet manually
        // We need to build FacetCut array and call LibDiamond directly
        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);

        // Build the selector array for DiamondCutFacet
        // It only has one function: diamondCut(FacetCut[], address, bytes)
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = IDiamondCut.diamondCut.selector;

        cut[0] = IDiamondCut.FacetCut({
            facetAddress: _diamondCutFacet, action: IDiamondCut.FacetCutAction.Add, functionSelectors: functionSelectors
        });

        // Call LibDiamond directly - no ownership check needed here
        // because we ARE the constructor, there is no other caller
        LibDiamond.diamondCut(cut, address(0), "");
    }

    /**
     * @notice Transfer Diamond ownership to a new address.
     * @dev Only current owner can call this.
     *      Used by factory after deployment to hand off to user.
     *      Same pattern GardenFactory will use — deploy with factory
     *      as temp owner, install facets, transfer to real user.
     *
     * @param _newOwner Address to transfer ownership to
     */
    function transferOwnership(address _newOwner) external {
        LibDiamond.enforceIsContractOwner();
        LibDiamond.setContractOwner(_newOwner);
    }

    /**
     * @notice Routes all calls to the appropriate facet.
     * @dev This is the core of the Diamond pattern.
     *      Every function call that isn't in Diamond.sol lands here.
     *
     *      WHY ASSEMBLY:
     *      1. Gas efficiency - no solidity overhead on every single call
     *      2. Control - we forward return data and revert data exactly,
     *         including revert reasons from facets
     *      3. delegatecall requires manual return data handling anyway
     */

    fallback() external payable {
        LibDiamond.DiamondStorage storage ds;
        bytes32 position = LibDiamond.DIAMOND_STORAGE_POSITION;

        // Load the DiamondStorage struct from its fixed slot
        assembly {
            ds.slot := position
        }

        // Look up which facet handles this function selector
        // msg.sig is the first 4 bytes of msg.data - the function selector
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;

        // If no facet is registered for this selector, revert
        if (facet == address(0)) revert FunctionNotFound(msg.sig);

        // delegatecall the facet with the original callddata
        // Run facet's code in Diamond's storage context
        assembly {
            // Copy calldata to memory starting at position 0
            calldatacopy(0, 0, calldatasize())

            // delegatecall:
            // gas()        → forward all remaining gas
            // facet        → the contract whose code we borrow
            // 0            → calldata starts at memory position 0
            // calldatasize → how many bytes of calldata
            // 0,0          → we don't know return size yet, handle below
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)

            // Copy the return data to memory position 0
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 {
                // delegatecall failed - forward the revert reason
                revert(0, returndatasize())
            }
            default {
                // delegatecall succeeded - return the result
                return(0, returndatasize())
            }
        }
    }

    /**
     * @notice Accept ETH transfers directly.
     * @dev Without this, sending ETH to the Diamond reverts.
     *      Users need to fund their Garden - this makes it possible
     */
    receive() external payable {}
}
