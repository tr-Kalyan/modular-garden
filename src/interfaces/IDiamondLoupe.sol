// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDiamondLoupe
 * @notice Read-only introspection interface for a Diamond.
 * @dev ERC-2535 requires every Diamond implement these four functions.
 *      They answer the question: "what is currently in this routing table?"
 *
 * WHY THIS EXISTS:
 * diamondCut() is a write side - it modifies the routing table.
 * DiamondLoupe is the read side - it exposes what's in the table.
 * Without this , Diamond is a black box nobody can audit or inspect.
 */

interface IDiamondLoupe {
    /**
     * @notice A facet address paired with all its registered selectors.
     * @dev Used as a return type - not used as input anywhere.
     *      One Facet struct = one deployed facet contract + every function it handles.
     */
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    /**
     * @notice Returns ALL facets and their selectors currently in the Diamond.
     * @dev This is the full routing table exposed as an array.
     */

    function facets() external view returns (Facet[] memory facets_);

    /**
     * @notice Returns all function selectors handled by a specific facet.
     * @param _facet The facet address to query.
     */

    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory facetFunctionSelectors_);

    /**
     * @notice Returns all facetAddresses currently in the Diamond.
     * @dev Lighter than facets() - just addresses, no selectors.
     *      Useful for quickly checking how many facets are installed.
     */

    function facetAddresses() external view returns (address[] memory facetAddresses_);

    /**
     * @notice Returns which facet handles a given function selector.
     * @param _functionSelector The 4-byte selector to look up.
     * @return facetAddress_ The facet that handles this selector.
     *                       Returns address(0) if selector is not registered.
     *
     * THIS IS THE ROUTING TABLE LOOKUP — exposed publicly.
     * The Diamond's fallback does this same lookup internally on every call.
     * This function makes that lookup visible to tooling and auditors.
     */
    function facetAddress(bytes4 _functionSelector) external view returns (address facetAddress_);
}
