// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IDiamondCut
 * @notice Interface for adding, replacing, and removing facets on a Diamond.
 * @dev ERC-2535 compliant. Any contract that implements diamongCut() is a Diamond.
 *
 * Mental Model:
 * A Diamond is just a routing table.
 * The table maps: function selectors (bytes4) → facet address
 * diamondCut() is the ONLY way to modify the table
 */

interface IDiamondCut {
    /**
     * @notice Three operations you can perform on a facet.
     *
     * Add → new selectors, new facet address. Function didn't exist before.
     * Replace → existing selectors, new facet address. Upgrading logic.
     * Remove → existing selectors removed. Function no longer exists on the Diamond.
     */
    enum FacetCutAction {
        Add, // 0
        Replace, // 1
        Remove // 2
    }

    /**
     * @notice Describes one facet operation in a diamond call.
     *
     * @param facetAddress Adress of the facet contract.
     *                     For Remove operations this MUST be address(0)
     * @param action Add, Replace, Remove.
     * @param functionSelectors The 4-byte selectors being added/replaced/removed.
     */

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    /**
     * @notice Modify the Diamond's routing table
     *
     * @param _diamondCut Array of FacetCut structs. Can mix Add/Replace/Remove in one atomic transaction
     * @param _init  Address to delegatecall after cuts are applied.
     *               address(0) = no initialization needed.
     * @param _calldata  Calldata for the _init delegateCall
     *                   Ignored if _init is address(0)
     * WHY _init EXISTS:
     * When you add a new facet, sometimes you need to initialize its storage.
     * You can't call a constructor (this is proxy).
     * So you pass an initializer contract address + calldata.
     * The Diamond delegatecalls it right after applying the cuts.
     */
    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external;

    /**
     * @notice Emitted everytime the routing table changes.
     * @dev Auditors and indexers rely on this event to tract proxy state.
     */
    event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
}
