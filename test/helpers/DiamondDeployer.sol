// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Diamond} from "../../src/Diamond.sol";
import {DiamondCutFacet} from "../../src/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../../src/facets/DiamondLoupeFacet.sol";
import {RiskParamsFacet} from "../../src/facets/RiskParamsFacet.sol";
import {ManagerFacet} from "../../src/facets/ManagerFacet.sol";
import {IDiamondCut} from "../../src/interfaces/IDiamondCut.sol";
import {IDiamondLoupe} from "../../src/interfaces/IDiamondLoupe.sol";
import {ECDSAValidatorFacet} from "../../src/facets/ECDSAValidatorFacet.sol";

/**
 * @title DiamondDeployer
 * @notice Test helper that deploys a full configured Diamond.
 * @dev Used in every test file. Deploy once in setUp(), use everywhere.
 */
contract DiamondDeployer {
    // Deployed contract references
    Diamond public diamond;
    DiamondCutFacet public diamondCutFacet;
    DiamondLoupeFacet public diamondLoupeFacet;
    RiskParamsFacet public riskParamsFacet;
    ManagerFacet public managerFacet;
    ECDSAValidatorFacet public ecdsaValidatorFacet;

    // Facet interfaces cast to Diamond address
    // This is how we call facet functions in tests
    // cast the Diamond address to the facet interface
    IDiamondCut public iDiamondCut;
    IDiamondLoupe public iDiamondLoupe;
    RiskParamsFacet public iRiskParams;
    ManagerFacet public iManager;

    /**
     * @notice Deploy Diamond with all facets installed
     * @param _owner The address that will own this Diamond
     */
    function deploy(address _owner) public returns (Diamond) {
        // Step 1 - Deploy all facets contracts
        // These are the stateless logic containers - deploying them
        // does not set any storage, just makes code available
        diamondCutFacet = new DiamondCutFacet();
        diamondLoupeFacet = new DiamondLoupeFacet();
        riskParamsFacet = new RiskParamsFacet();
        managerFacet = new ManagerFacet();
        ecdsaValidatorFacet = new ECDSAValidatorFacet();

        // Step 2 - Deploy Diamond with owner + DiamondCutFacet
        // Constructor registers DiamondCutFacet automatically
        diamond = new Diamond(address(this), address(diamondCutFacet));

        // Step 3 - Build the cut array from remaining facets
        // Each FacetCut says: add these selectors from this facet
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](4);

        // DiamondLoupeFacet - 4 selectors
        bytes4[] memory loupeSelectors = new bytes4[](4);
        loupeSelectors[0] = IDiamondLoupe.facets.selector;
        loupeSelectors[1] = IDiamondLoupe.facetFunctionSelectors.selector;
        loupeSelectors[2] = IDiamondLoupe.facetAddresses.selector;
        loupeSelectors[3] = IDiamondLoupe.facetAddress.selector;

        cuts[0] = IDiamondCut.FacetCut({
            facetAddress: address(diamondLoupeFacet),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: loupeSelectors
        });

        // RiskParamsFacet selectors
        bytes4[] memory riskSelectors = new bytes4[](7);
        riskSelectors[0] = RiskParamsFacet.initializeRiskParams.selector;
        riskSelectors[1] = RiskParamsFacet.setDailySpendLimit.selector;
        riskSelectors[2] = RiskParamsFacet.setMaxPositionSize.selector;
        riskSelectors[3] = RiskParamsFacet.addAllowedProtocol.selector;
        riskSelectors[4] = RiskParamsFacet.removeAllowedProtocol.selector;
        riskSelectors[5] = RiskParamsFacet.getRiskParams.selector;
        riskSelectors[6] = RiskParamsFacet.isProtocolAllowed.selector;

        cuts[1] = IDiamondCut.FacetCut({
            facetAddress: address(riskParamsFacet),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: riskSelectors
        });

        // ManagerFacet selectors
        bytes4[] memory managerSelectors = new bytes4[](6);
        managerSelectors[0] = ManagerFacet.initializeManager.selector;
        managerSelectors[1] = ManagerFacet.setManager.selector;
        managerSelectors[2] = ManagerFacet.revokeManager.selector;
        managerSelectors[3] = ManagerFacet.execute.selector;
        managerSelectors[4] = ManagerFacet.getManager.selector;
        managerSelectors[5] = ManagerFacet.isManager.selector;

        cuts[2] = IDiamondCut.FacetCut({
            facetAddress: address(managerFacet),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: managerSelectors
        });

        bytes4[] memory validatorSelectors = new bytes4[](4);
        validatorSelectors[0] = ECDSAValidatorFacet.initializeValidator.selector;
        validatorSelectors[1] = ECDSAValidatorFacet.validateUserOp.selector;
        validatorSelectors[2] = ECDSAValidatorFacet.setValidatorOwner.selector;
        validatorSelectors[3] = ECDSAValidatorFacet.getValidatorOwner.selector;

        cuts[3] = IDiamondCut.FacetCut({
            facetAddress: address(ecdsaValidatorFacet),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: validatorSelectors
        });

        // Step 4 — Execute the cut as owner
        // Cast Diamond to IDiamondCut to call diamondCut()
        // This goes through Diamond's fallback → DiamondCutFacet
        IDiamondCut(address(diamond)).diamondCut(cuts, address(0), "");

        // Step 5 — Transfer ownership to real owner
        // msg.sender here = DiamondDeployer = current owner → passes check
        Diamond(payable(address(diamond))).transferOwnership(_owner);

        // Step 6 — Set interface references
        iDiamondCut = IDiamondCut(address(diamond));
        iDiamondLoupe = IDiamondLoupe(address(diamond));
        iRiskParams = RiskParamsFacet(address(diamond));
        iManager = ManagerFacet(address(diamond));

        return diamond;
    }
}
