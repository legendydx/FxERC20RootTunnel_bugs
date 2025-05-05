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

Root Cause: Insufficient access control and validation in `withdrawLeftAssetsAfterFinalized`, allowing `DEFAULT_ADMIN_ROLE` holders to withdraw arbitrary tokens without oversight. See Genesis.

Impact

-Fund Loss: A malicious or compromised admin can drain all `virtualToken` or `agentToken` held by the contract, stealing participant contributions or rewards.

-Protocol Disruption: Unauthorized withdrawals undermine trust in the genesis event, potentially collapsing the protocol’s economy.

-Severity: High, due to direct financial loss and systemic impact.


## Recommended Mitigation
1. **Restrict Withdrawal Destination**: Limit the `to` address to a predefined treasury or multisig wallet:
   ```solidity
   address public immutable treasury;
   constructor(address _treasury) {
       treasury = _treasury;
   }
   function withdrawLeftAssetsAfterFinalized(address to, address token, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
       require(to == treasury, "Invalid destination");
       // ... rest of function
   }
   ```

   2. **Add Validation**: Ensure withdrawals only occur for truly leftover assets (e.g., after all refunds and distributions).
3. **Implement Timelock**: Use a timelock for withdrawals to allow community oversight:
   ```solidity
   import "@openzeppelin/contracts/governance/TimelockController.sol";
   ```

   
## Tools Used
- Manual code review

## References
- [OpenZeppelin AccessControl Documentation](https://docs.openzeppelin.com/contracts/4.x/access-control)
- [Solidity Documentation on Access Control](https://docs.soliditylang.org/en/v0.8.26/control-structures.html)