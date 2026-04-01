// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondCut} from "../interfaces/IDiamondCut.sol";

/**
 * @title LibDiamond
 * @notice Core library for Diamond routing table storage and management
 * @dev This library owns the routing table - the mapping from function selector
 *      to facet address. Everything in the Diamond reads/writes through here.
 *
 *
 *      WHY A LIBRARY:
 *          Three contracts need this logic — Diamond proxy, DiamondCutFacet,
 *          DiamondLoupeFacet. A library lets all three share it without
 *          inheritance chains or duplicated code.
 *      WHY NOT ERC-7201 HERE:
 *          LibDiamond uses Diamond Storage pattern (a single struct at a fixed slot).
 *          Our FACETS use ERC-7201. These are different concerns:
 *          - LibDiamond stores routing infrastructure (who handles what selector)
 *          - Facets store business data (balances, limits, manager address)
 *          Keeping them separate means upgrading a facet never touches routing data.
 */

library LibDiamond {
    error NotContractOwner(address user, address contractOwner);
    error IncorrectFacetCutAction();
    error CannotAddFunctionToDiamondWithoutFacet();
    error NoSelectorsProvidedForFacetForCut(address _facetAddress);
    error CannotAddSelectorsAlreadyInContract(bytes4 selector);
    error CannotReplaceFunctionsFromFacetWithZeroAddress();
    error CannotReplaceFunctionWithSameFunction(bytes4 selector);
    error CannotReplaceFunctionThatDoesNotExist(bytes4 selector);
    error CannotRemoveFunctionThatDoesNotExist(bytes4 selector);
    error RemoveFacetAddressMustBeZeroAddress(address _facetAddress);
    error NoBytecodeAtAddress(address _contract);
    error InitializationFunctionReverted(address _init, bytes _calldata);

    /**
     * @dev Storage slot for the Diamond routing table.
     *      Computed as keccak256("diamond.standard.diamond.storage") - 1
     *      The -1 prevents a preimage attack where someone crafts input
     *      that hashes to this shot.
     *      This value never changes. It is the anchor of the entire system.
     */

    bytes32 constant DIAMOND_STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256("diamond.standard.diamond.storage")) - 1));

    /**
     * @notice The core routing table struct.
     * @dev Stored at DIAMOND_STORAGE_POSITION in the Diamond's storage.
     *
     * selectorToFacetAndPosition:
     *      The main routing table. Given  a bytes4 selector, tells you:
     *      - which facet handles it
     *      - where in that facet's selector array it sits (for efficient removal)
     *
     * facetFunctionSelectors:
     *      Reverse lookup. Given a facet address, what selectors does it handle ?
     *      Also tracks the facet's position in the facetAddresses array.
     *
     * facetAddresses:
     *      All facet addresses currently installed. Used by DiamondLoupe
     *
     * ContractOwner:
     *      Only the owner can call diamondCut. This is your access control.
     */

    struct FacetAddressAndPosition {
        address facetAddress;
        uint96 functionSelectorPosition; // position in facetFunctionSelectors[facetAddress].functionSelectors array
    }

    struct FacetFunctionSelectors {
        bytes4[] functionSelectors;
        uint256 facetAddressPosition; // position in facetAddresses array
    }

    struct DiamondStorage {
        // selector → facet address + position in selector array
        mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;

        // facet address → selectors it handles + position in facetAdddresses
        mapping(address => FacetFunctionSelectors) facetFunctionSelectors;

        // all facet addresses
        address[] facetAddresses;

        // owner of this Diamond — only they can cut
        address contractOwner;
    }

    /**
     * @notice Returns a referece to the DiamondStorage struct.
     * @dev Uses assembly to load the struct from its fixed storage slot.
     *      Every readwrite to routing data goes through this function.
     *
     *      PATTERN: ds.selectorToFacetAndPosition[selector] to read
     *               ds.contractOwner to check ownership
     */

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Transfer Diamond ownership
     * @dev Emits OwnershipTransferred. Used during factory deployment
     *      to set the user as owner after the Diamond is deployed.
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setContractOwner(address _newOwner) internal {
        DiamondStorage storage ds = diamondStorage();
        address previousOwner = ds.contractOwner;
        ds.contractOwner = _newOwner;
        emit OwnershipTransferred(previousOwner, _newOwner);
    }

    function contractOwner() internal view returns (address contractOwner_) {
        contractOwner_ = diamondStorage().contractOwner;
    }

    /**
     * @notice Revert if caller is not the Diamond owner.
     * @dev Called at the top of diamondCut. If this passes, the cut proceeds.
     */
    function enforceIsContractOwner() internal view {
        if (msg.sender != diamondStorage().contractOwner) {
            revert NotContractOwner(msg.sender, diamondStorage().contractOwner);
        }
    }

    /**
     * @notice Internal implementation of diamondCut.
     * @dev Called by DiamondCutFacet.diamondCut() after ownership check.
     *      Loops through each FacetCut and dispatches to add/remove/replace.
     *      After all cuts, calls the initializer if provided.
     */

    function diamondCut(IDiamondCut.FacetCut[] memory _diamondCut, address _init, bytes memory _calldata) internal {
        for (uint256 facetIndex; facetIndex < _diamondCut.length;) {
            IDiamondCut.FacetCutAction action = _diamondCut[facetIndex].action;

            if (action == IDiamondCut.FacetCutAction.Add) {
                addFunctions(_diamondCut[facetIndex].facetAddress, _diamondCut[facetIndex].functionSelectors);
            } else if (action == IDiamondCut.FacetCutAction.Replace) {
                replaceFunctions(_diamondCut[facetIndex].facetAddress, _diamondCut[facetIndex].functionSelectors);
            } else if (action == IDiamondCut.FacetCutAction.Remove) {
                removeFunctions(_diamondCut[facetIndex].facetAddress, _diamondCut[facetIndex].functionSelectors);
            } else {
                revert IncorrectFacetCutAction();
            }
            unchecked {
                ++facetIndex;
            }
        }

        // Emit BEFORE initializer - event captures the cut, init is a side effect
        emit IDiamondCut.DiamondCut(_diamondCut, _init, _calldata);
        initializeDiamondCut(_init, _calldata);
    }

    function addFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        if (_facetAddress == address(0)) revert CannotAddFunctionToDiamondWithoutFacet();
        if (_functionSelectors.length == 0) revert NoSelectorsProvidedForFacetForCut(_facetAddress);

        DiamondStorage storage ds = diamondStorage();
        uint96 selectorPosition = uint96(ds.facetFunctionSelectors[_facetAddress].functionSelectors.length);

        // if this is a new facet address, add it to the facetAddress array
        if (selectorPosition == 0) {
            addFacet(ds, _facetAddress);
        }

        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length;) {
            bytes4 selector = _functionSelectors[selectorIndex];
            address oldFacetAddress = ds.selectorToFacetAndPosition[selector].facetAddress;

            // cannot add a selector that already exists
            if (oldFacetAddress != address(0)) revert CannotAddSelectorsAlreadyInContract(selector);

            addFunction(ds, selector, selectorPosition, _facetAddress);
            unchecked {
                ++selectorPosition;
                ++selectorIndex;
            }
        }
    }

    function replaceFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        if (_facetAddress == address(0)) revert CannotReplaceFunctionsFromFacetWithZeroAddress();
        if (_functionSelectors.length == 0) revert NoSelectorsProvidedForFacetForCut(_facetAddress);

        DiamondStorage storage ds = diamondStorage();
        uint96 selectorPosition = uint96(ds.facetFunctionSelectors[_facetAddress].functionSelectors.length);

        // If new facet address hasn't been registered yet, register it
        // The SELECTOR must exist, but the new facet address may be brand new
        if (selectorPosition == 0) {
            addFacet(ds, _facetAddress);
        }

        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length;) {
            bytes4 selector = _functionSelectors[selectorIndex];
            address oldFacetAddress = ds.selectorToFacetAndPosition[selector].facetAddress;

            // Cannot replace with same facet
            if (oldFacetAddress == _facetAddress) revert CannotReplaceFunctionWithSameFunction(selector);

            // Must exist to replace
            if (oldFacetAddress == address(0)) revert CannotReplaceFunctionThatDoesNotExist(selector);

            removeFunction(ds, oldFacetAddress, selector);
            addFunction(ds, selector, selectorPosition, _facetAddress);
            unchecked {
                ++selectorPosition;
                ++selectorIndex;
            }
        }
    }

    function removeFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        if (_facetAddress != address(0)) revert RemoveFacetAddressMustBeZeroAddress(_facetAddress);
        if (_functionSelectors.length == 0) revert NoSelectorsProvidedForFacetForCut(_facetAddress);

        DiamondStorage storage ds = diamondStorage();

        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length;) {
            bytes4 selector = _functionSelectors[selectorIndex];
            address oldFacetAddress = ds.selectorToFacetAndPosition[selector].facetAddress;

            // Must exist to remove
            if (oldFacetAddress == address(0)) revert CannotRemoveFunctionThatDoesNotExist(selector);

            removeFunction(ds, oldFacetAddress, selector);
            unchecked {
                ++selectorIndex;
            }
        }
    }

    function addFacet(DiamondStorage storage ds, address _facetAddress) internal {
        enforceHasContractCode(_facetAddress);
        ds.facetFunctionSelectors[_facetAddress].facetAddressPosition = ds.facetAddresses.length;
        ds.facetAddresses.push(_facetAddress);
    }

    function addFunction(DiamondStorage storage ds, bytes4 _selector, uint96 _selectorPosition, address _facetAddress)
        internal
    {
        ds.selectorToFacetAndPosition[_selector].functionSelectorPosition = _selectorPosition;
        ds.facetFunctionSelectors[_facetAddress].functionSelectors.push(_selector);
        ds.selectorToFacetAndPosition[_selector].facetAddress = _facetAddress;
    }

    function removeFunction(DiamondStorage storage ds, address _facetAddress, bytes4 _selector) internal {
        // Get position of selector in the facet's selector array
        uint256 selectorPosition = ds.selectorToFacetAndPosition[_selector].functionSelectorPosition;
        uint256 lastSelectorPosition = ds.facetFunctionSelectors[_facetAddress].functionSelectors.length - 1;

        // swap with last element if not already last - O(1) removal
        if (selectorPosition != lastSelectorPosition) {
            // Get the last selector in the facet array
            bytes4 lastSelector = ds.facetFunctionSelectors[_facetAddress].functionSelectors[lastSelectorPosition];

            // Replace the current selector with last selector
            ds.facetFunctionSelectors[_facetAddress].functionSelectors[selectorPosition] = lastSelector;

            // update the last selector position in the selectorToFacetAndPosition struct
            ds.selectorToFacetAndPosition[lastSelector].functionSelectorPosition = uint96(selectorPosition);
        }

        // Pop last element
        ds.facetFunctionSelectors[_facetAddress].functionSelectors.pop();
        delete ds.selectorToFacetAndPosition[_selector];

        // If facet has no more selectors, remove it from facetAddresses
        if (lastSelectorPosition == 0) {
            uint256 facetAddressPosition = ds.facetFunctionSelectors[_facetAddress].facetAddressPosition;
            uint256 lastFacetAddressPosition = ds.facetAddresses.length - 1;

            if (facetAddressPosition != lastFacetAddressPosition) {
                address lastFacetAddress = ds.facetAddresses[lastFacetAddressPosition];
                ds.facetAddresses[facetAddressPosition] = lastFacetAddress;
                ds.facetFunctionSelectors[lastFacetAddress].facetAddressPosition = facetAddressPosition;
            }

            ds.facetAddresses.pop();
            delete ds.facetFunctionSelectors[_facetAddress];
        }
    }

    /**
     *
     * @notice Delegatecalls the initializer after cuts are applied.
     * @dev This runs in the Diamond's storage context - exactly what you want
     *      for setting up acet storage after adding a new facet.
     */

    function initializeDiamondCut(address _init, bytes memory _calldata) internal {
        if (_init == address(0)) return;

        enforceHasContractCode(_init);

        (bool success, bytes memory error) = _init.delegatecall(_calldata);
        if (!success) {
            if (error.length > 0) {
                assembly {
                    revert(add(32, error), mload(error))
                }
            } else {
                revert InitializationFunctionReverted(_init, _calldata);
            }
        }
    }

    /**
     * @notice Revert if address has no deployed code.
     * @dev Protects against accidentally pointing selectors at EOAs or
     *      undeployed contracts.An EOA has no code - calling it would
     *      silently success and do nothing. This catches that.
     */
    function enforceHasContractCode(address _contract) internal view {
        uint256 contractSize;
        assembly {
            contractSize := extcodesize(_contract)
        }
        if (contractSize == 0) revert NoBytecodeAtAddress(_contract);
    }
}
