// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondLoupe} from "../interfaces/IDiamondLoupe.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

/**
 * @title DiamondLoupeFacet
 * @notice Read-only introspection for the Diamond routing table.
 * @dev ERC-2535 requires every diamond implements these four functions.
 *      They make the Diamond transparent - auditors, block exploreres.
 *      and tools like louper.dev use these to inspect the contract
 *
 *      WHY NO LOGIC HERE:
 *      Everything reads directly from LibDiamond.diamondStorage().
 *      The routing table is the single source of truth.
 */

contract DiamondLoupeFacet is IDiamondLoupe {
    /**
     * @notice Returns all facets and their registered selectors.
     * @dev This is the full routing table as a human-readable array.
     *      Call this before and after a diamondCut to verify what changed.
     *
     *      HOW IT WORKS:
     *      1. Get all facet addresses from storage
     *      2. For each address, get its selector array
     *      3. Package both into a Facet struct
     *      4. Return the array
     */
    function facets() external view override returns (Facet[] memory facets_) {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        uint256 numFacets = ds.facetAddresses.length;

        // Allocate return array — one slot per registered facet
        facets_ = new Facet[](numFacets);

        for (uint256 i; i < numFacets;) {
            address facetAddr = ds.facetAddresses[i];
            facets_[i].facetAddress = facetAddr;
            facets_[i].functionSelectors = ds.facetFunctionSelectors[facetAddr].functionSelectors;
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Returns all selectors registered to a specific facet address.
     * @dev Use this to answer: "what functions does AaveFacet handle right now?"
     *      Returns empty array if facet is not registered.
     *
     * @param _facet The facet address to query
     */
    function facetFunctionSelectors(address _facet)
        external
        view
        override
        returns (bytes4[] memory facetFunctionSelectors_)
    {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        facetFunctionSelectors_ = ds.facetFunctionSelectors[_facet].functionSelectors;
    }

    /**
     * @notice Returns all facet addresses currently installed.
     * @dev Lighter than facets() — addresses only, no selectors.
     *      Useful for quickly checking how many facets are installed
     *      without loading all selector arrays.
     */
    function facetAddresses() external view override returns (address[] memory facetAddresses_) {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        facetAddresses_ = ds.facetAddresses;
    }

    /**
     * @notice Returns which facet handles a given selector.
     * @dev This is the same lookup the fallback() does on every live call —
     *      just exposed publicly for tooling and auditors.
     *      Returns address(0) if selector is not registered.
     *
     * @param _functionSelector The 4-byte selector to look up
     *
     * EXAMPLE:
     * bytes4 selector = bytes4(keccak256("deposit(uint256)"));
     * address facet = diamond.facetAddress(selector);
     * // facet == AaveFacet address if deposit is registered
     */
    function facetAddress(bytes4 _functionSelector) external view override returns (address facetAddress_) {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        facetAddress_ = ds.selectorToFacetAndPosition[_functionSelector].facetAddress;
    }
}
