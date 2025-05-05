# [H-03] Missing Role Validation in `onGenesisSuccess` Enables Unauthorized Token Distribution

## Summary
The `onGenesisSuccess` function in `Genesis.sol` is restricted to `FACTORY_ROLE` but lacks validation for the `distributeAgentTokenUserAddresses` and `distributeAgentTokenUserAmounts` arrays, allowing the factory to distribute `agentToken` to arbitrary addresses. A malicious or compromised factory could misallocate tokens, leading to fund loss and unfair outcomes.

## Vulnerability Details
The `onGenesisSuccess` function is defined as:

```solidity
function onGenesisSuccess(
    address[] calldata refundVirtualsTokenUserAddresses,
    uint256[] calldata refundVirtualsTokenUserAmounts,
    address[] calldata distributeAgentTokenUserAddresses,
    uint256[] calldata distributeAgentTokenUserAmounts,
    address creator
) external onlyRole(FACTORY_ROLE) nonReentrant whenNotCancelled whenNotFailed whenEnded returns (address) {
    // ... validation for refunds
    for (uint256 i = 0; i < distributeAgentTokenUserAddresses.length; i++) {
        claimableAgentTokens[distributeAgentTokenUserAddresses[i]] = distributeAgentTokenUserAmounts[i];
    }
    // ... rest of function
}
```


While it checks array lengths and refund amounts, it does not validate:
- If `distributeAgentTokenUserAddresses` are legitimate participants (e.g., in `participants`).
- If `distributeAgentTokenUserAmounts` are proportional to contributions or within bounds.

A malicious factory could distribute `agentToken` to non-participants or allocate excessive amounts, bypassing the intended distribution logic.

**Root Cause**: Lack of validation for `distributeAgentTokenUserAddresses` and `distributeAgentTokenUserAmounts` in `onGenesisSuccess`. 


## Impact
- **Fund Loss**: Malicious distributions could divert `agentToken` to unauthorized addresses, depriving legitimate participants.
- **Unfair Outcomes**: Incorrect allocations could skew governance or economic rewards, undermining the genesis event.
- **Severity**: High, due to financial loss and protocol disruption.

Due to the multifaceted nature of the flaws in the codes mentioned, i could'nt come up with a succesfull Poc(proof of concept) to demostrate their real impact. Nevertheless, they are high severity loopholes that has to be addressed before any catostrophic outcomes.