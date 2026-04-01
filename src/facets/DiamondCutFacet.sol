// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondCut} from "../interfaces/IDiamondCut.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

/**
 * @title DiamondCutFacet
 * @notice The only facet that can modify the Diamond's routing table
 * @dev This facet is registered in the Diamond constructor before anything else.
 *      Without it, no other facets can ever be added.
 */

contract DiamondCutFacet is IDiamondCut {
    /**
     * @notice Add, replace, or remove facets on this Diamond.
     * @dev Only the Diamond owner can call this.
     *      Reverts if msg.sender is not contractOwner.
     *
     * @param _diamondCut   Array of facet chanegs to apply atomically
     * @param _init         Initializer contract address (address(0) = none)
     * @param _calldata     Calldata for initializer delegatecall
     *
     * ATOMICITY:
     * All cuts in _diamondCut either all succeed or all revert.
     * Partial upgrade is not possible. This is critical for safety.
     * A half-applied upgrade could leave the Diamond in a broken state.
     */
    function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external override {
        // Ownership check
        LibDiamond.enforceIsContractOwner();

        // Hand off to LibDiamond which does the actual work
        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
    }
}
