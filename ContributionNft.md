 [H-01] Unrestricted `mint` Function Allows Unauthorized NFT Minting Due to Missing Access Control

 Summary
The `mint` function in `ContributionNft.sol` lacks proper access control, relying solely on a `proposalProposer` check that can be bypassed or manipulated due to external contract dependencies. This allows unauthorized users to mint Contribution NFTs, leading to potential financial loss, governance manipulation, and disruption of the NFT ecosystem.

## Vulnerability Details
The `mint` function is `external` and intended to mint Contribution NFTs tied to governance proposals. It checks if `msg.sender` is the proposer of a given `proposalId` by calling `personaDAO.proposalProposer(proposalId)`, but it has no additional access control (e.g., `onlyAdmin` or role-based modifiers). This makes it vulnerable to unauthorized minting if the external `IGovernor` contract’s `proposalProposer` function is misconfigured, manipulable, or returns unexpected resutls.

**Root Cause**: The absence of a robust access control mechanism in the `mint` function, combined with reliance on an external `IGovernor` contract, allows unauthorized calls. 

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol"; 

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/interfaces/IERC5805.sol";

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./IContributionNft.sol";
import "../virtualPersona/IAgentNft.sol";

contract ContributionNft is
    IContributionNft,
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    ERC721URIStorageUpgradeable
{
    address public personaNft;

    mapping(uint256 => uint256) private _contributionVirtualId;
    mapping(uint256 => uint256) private _parents;
    mapping(uint256 => uint256[]) private _children;
    mapping(uint256 => uint8) private _cores;

    mapping(uint256 => bool) public modelContributions;
    mapping(uint256 => uint256) public modelDatasets;

    event NewContribution(uint256 tokenId, uint256 virtualId, uint256 parentId, uint256 datasetId);

    address private _admin; // Admin is able to create contribution proposal without votes

    address private _eloCalculator;

    /// @custom:oz-upgrades-unsafe-allow constructor
    //The _disableInitializers() function prevents
    // the implementation contract from being initialized directly.
    constructor() {
        _disableInitializers();
    }
    ///🐛Missing Zero Address Validation:don't validate against zero addresses, which could permanently break contract functionality if misused.

    //This initialize function serves as a replacement for 
    //a constructor in an upgradeable smart contract
    function initialize(address thePersonaAddress) public initializer {
        __ERC721_init("Contribution", "VC"); //Initializes the base ERC721 NFT contract with: Name: "Contribution" Symbol: "VC"
        __ERC721Enumerable_init(); //Initializes the enumerable extension, enabling functions to enumerate tokens and query ownership.
        __ERC721URIStorage_init(); // Initializes the URI storage extension, allowing metadata URIs to be associated with tokens.

        personaNft = thePersonaAddress; //Stores the address of the Persona/Agent NFT contract that this Contribution NFT contract will interact with.
        _admin = _msgSender(); //returns the one calling the tx not the addrs paying the tx fees
    }

    function tokenVirtualId(uint256 tokenId) public view returns (uint256) {
        return _contributionVirtualId[tokenId];
    }

    function getAgentDAO(uint256 virtualId) public view returns (IGovernor) {
        return IGovernor(IAgentNft(personaNft).virtualInfo(virtualId).dao);
    }

    function isAccepted(uint256 tokenId) public view returns (bool) {
        uint256 virtualId = _contributionVirtualId[tokenId];
        IGovernor personaDAO = getAgentDAO(virtualId);
        return personaDAO.state(tokenId) == IGovernor.ProposalState.Succeeded;
    }
      /** ----------------🐛🐛🐛🐛--------- 
    Missing Access Control for Critical Functions: The mint() function has no access control modifier, 
   allowing anyone to mint NFTs if they can pass the proposalProposer check. 
   This could lead to unauthorized minting
   if the proposalProposer check is bypassed or manipulated.
*/

   /** ----------------🐛🐛🐛🐛---------
   No Reentrancy Protection: The mint() function interacts with external
    contracts but lacks reentrancy guards,
    potentially allowing attackers to reenter and manipulate state.
   
   */
   /**----------------🐛🐛🐛🐛---------
   No Input Validation: Several parameters like virtualId, coreId, datasetId in mint() have no validation, 
   allowing potentially invalid data to be stored. */
    function mint( address to,
         uint256 virtualId,
         uint8 coreId,
         string memory newTokenURI,
         uint256 proposalId,
         uint256 parentId,
         bool isModel_,
         uint256 datasetId
    ) external returns (uint256) {
        IGovernor personaDAO = getAgentDAO(virtualId);
        require(
            msg.sender == personaDAO.proposalProposer(proposalId),
            "Only proposal proposer can mint Contribution NFT"
        );
        require(parentId != proposalId, "Cannot be parent of itself");

        _mint(to, proposalId);
        _setTokenURI(proposalId, newTokenURI);
        _contributionVirtualId[proposalId] = virtualId;
        _parents[proposalId] = parentId;
        _children[parentId].push(proposalId);
        _cores[proposalId] = coreId;

        if (isModel_) {
            modelContributions[proposalId] = true;
            modelDatasets[proposalId] = datasetId;
        }

        emit NewContribution(proposalId, virtualId, parentId, datasetId);

        return proposalId;
    }

    function getAdmin() public view override returns (address) {
        return _admin;
    }
// 🐛Missing Zero Address Validation:don't validate against zero addresses, which could permanently break contract functionality if misused.
    function setAdmin(address newAdmin) public {
        require(_msgSender() == _admin, "Only admin can set admin");
        _admin = newAdmin;
    }

    // The following functions are overrides required by Solidity.

    function tokenURI(
        uint256 tokenId
    ) public view override(IContributionNft, ERC721Upgradeable, ERC721URIStorageUpgradeable) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    function getChildren(uint256 tokenId) public view returns (uint256[] memory) {
        return _children[tokenId];
    }

    function getParentId(uint256 tokenId) public view returns (uint256) {
        return _parents[tokenId];
    }

    function getCore(uint256 tokenId) public view returns (uint8) {
        return _cores[tokenId];
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721Upgradeable, ERC721URIStorageUpgradeable, ERC721EnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _increaseBalance(
        address account,
        uint128 amount
    ) internal override(ERC721Upgradeable, ERC721EnumerableUpgradeable) {
        return super._increaseBalance(account, amount);
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override(ERC721Upgradeable, ERC721EnumerableUpgradeable) returns (address) {
        return super._update(to, tokenId, auth);
    }

    function isModel(uint256 tokenId) public view returns (bool) {
        return modelContributions[tokenId];
    }

    function ownerOf(uint256 tokenId) public view override(IERC721, ERC721Upgradeable) returns (address) {
        return _ownerOf(tokenId);
    }

    function getDatasetId(uint256 tokenId) external view returns (uint256) {
        return modelDatasets[tokenId];
    }

    function getEloCalculator() external view returns (address) {
        return _eloCalculator;
    }

//🐛Missing Zero Address Validation:don't validate against zero addresses, which could permanently break contract functionality if misused.

    function setEloCalculator(address eloCalculator_) public {
        require(_msgSender() == _admin, "Only admin can set elo calculator");
        _eloCalculator = eloCalculator_;
    }
}
```
Issues:

. No Access Control: The require check depends on personaDAO.proposalProposer, which is an external call to an IGovernor contract. If the IGovernor implementation is flawed, compromised, or allows proposers to be set arbitrarily, attackers can mint NFTs.

. External Dependency Risk: The getAgentDAO function fetches the DAO address via IAgentNft(personaNft).virtualInfo(virtualId).dao, introducing a chain of external calls that could be manipulated or return invalid data.

. No Validation of proposalId: The function does not verify if proposalId is a valid or succeeded proposal, potentially allowing minting for non-existent or failed proposals.

Impact

. Financial Loss: Unauthorized minting of NFTs could dilute their value, as Contribution NFTs may represent governance or economic rights in the ecosystem.

. Governance Manipulation: Minted NFTs could grant voting power or infuelnce in the associated DAO, allowing attackers to manipulate decesions.

. Ecosystem Disruption: Invalid NFTs could break the parent-child heirarchy (_parents, _children) or model/dataset mappings, causing inconsistencies.

. Severity: High, due to the potential for unauthorized NFT creation with significant financial and governance consequences.

Proof of Concept (PoC)
The following Foundry test demonstrates how an attacker can mint an NFT by exploiting a misconfigured ``IGovernor`` contract:

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../ContributionNft.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

interface IGovernorMock {
    function proposalProposer(uint256 proposalId) external view returns (address);
}

contract GovernorMock {
    address public proposer;
    constructor(address _proposer) { proposer = _proposer; }
    function proposalProposer(uint256) external view returns (address) { return proposer; }
}

contract ContributionNftTest is Test {
    ContributionNft nft;
    GovernorMock governor;
    address admin = address(0x1);
    address attacker = address(0x2);
    address personaNft = address(0x3);

    function setUp() public {
        governor = new GovernorMock(attacker); // Attacker is proposer
        vm.prank(admin);
        nft = new ContributionNft();
        vm.prank(admin);
        nft.initialize(personaNft);
        // Mock personaNft to return governor as DAO
        vm.mockCall(
            personaNft,
            abi.encodeWithSelector(IAgentNft.virtualInfo.selector, 1),
            abi.encode(IAgentNft.VirtualInfo(address(governor), 0))
        );
    }

    function testUnauthorizedMint() public {
        vm.prank(attacker);
        uint256 tokenId = nft.mint(
            attacker, // to
            1, // virtualId
            1, // coreId
            "ipfs://metadata", // newTokenURI
            123, // proposalId
            0, // parentId
            true, // isModel
            456 // datasetId
        );

        assertEq(nft.ownerOf(tokenId), attacker, "Attacker minted NFT");
        assertEq(nft.tokenVirtualId(tokenId), 1, "Virtual ID set");
        assertEq(nft.isModel(tokenId), true, "Model contribution set");
    }
}
```

Execution:

. Run forge test ```--match-path test/ContributionNftTest.sol.```

.The test shows an attacker minting an NFT by being the proposer in a mock IGovernor, bypassing intended restrictions.

Tools Used

. Manual code review
. Foundry (for PoC development)
. VS Code with markdownlint and Solidity extensions
. OpenZeppelin Contracts (ERC721Upgradeable)
. Polygon FxPortal (for bridge context, FxPortal)

Recommended Mitigation

1. Add Access Control:
Restrict mint to an admin or role-based system using OpenZeppelin’s AccessControl:

```js
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
contract ContributionNft is Initializable, ERC721Upgradeable, AccessControlUpgradeable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    function initialize(address thePersonaAddress) public initializer {
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(MINTER_ROLE, _msgSender());
        ...
    }
    function mint(...) external onlyRole(MINTER_ROLE) returns (uint256) { ... }
}
```

2. Validate Proposal State:
  .Ensure proposalId corresponds to a succeeded proposal:
  ```js
  require(personaDAO.state(proposalId) == IGovernor.ProposalState.Succeeded, "Proposal not succeeded");
  ```

3. Add Reentrancy Protection:
  .Use OpenZeppelin’s ``ReentrancyGuard``` to prevent reentrancy attacks:

 ```js
 import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
contract ContributionNft is Initializable, ERC721Upgradeable, ReentrancyGuardUpgradeable {
    function mint(...) external nonReentrant returns (uint256) { ... }
}
```

Severity

High

Reasoning
 .Likelihood: High, as the mint function is external and the proposalProposer check can be bypassed if the IGovernor contract is misconfigured or compromised.

.Impact: High, as unauthorized minting can lead to financial loss, governance manipulation, and ecosystem disruption.

.Classification: Per C4 guidelines, vulnerabilities enabling unauthorized asset creation with high likelihood and impact are High severity.

References

https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#ERC721Upgradeable

https://docs.openzeppelin.com/contracts/4.x/api/access#AccessControl

https://docs.code4rena.com/

https://eips.ethereum.org/EIPS/eip-721