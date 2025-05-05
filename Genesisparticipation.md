# [H-02] Public `participate` Function Lacks Input Validation, Enabling Malicious Contributions

## Summary
The `participate` function in `Genesis.sol` is public and lacks sufficient input validation for `pointAmt` and `virtualsAmt`, allowing malicious users to contribute invalid or excessive amounts. This could disrupt the genesis event’s logic, potentially leading to fund loss or unfair token distributions, undermining the protocol’s fairness and stability.


## Vulnerability Details
The `participate` function is defined as:

```solidity
function participate(uint256 pointAmt, uint256 virtualsAmt) external nonReentrant whenActive {
    require(pointAmt > 0, "Point amount must be greater than 0");
    require(virtualsAmt > 0, "Virtuals must be greater than 0");
    require(virtualsAmt <= maxContributionVirtualAmount, "Exceeds maximum virtuals per contribution");
    require(IERC20(virtualTokenAddress).balanceOf(msg.sender) >= virtualsAmt, "Insufficient Virtual Token balance");
    require(
        IERC20(virtualTokenAddress).allowance(msg.sender, address(this)) >= virtualsAmt,
        "Insufficient Virtual Token allowance"
    );

    if (mapAddrToVirtuals[msg.sender] == 0) {
        participants.push(msg.sender);
    }

    mapAddrToVirtuals[msg.sender] += virtualsAmt;

    IERC20(virtualTokenAddress).safeTransferFrom(msg.sender, address(this), virtualsAmt);

    emit Participated(genesisId, msg.sender, pointAmt, virtualsAmt);
}
```

While it includes checks for non-zero `pointAmt` and `virtualsAmt`, balance, allowance, and a maximum contribution limit, it lacks:
- Validation of `pointAmt`’s upper bound or its relationship to `virtualsAmt`.
- Checks to prevent overflow or excessive contributions within `maxContributionVirtualAmount`.
- Protection against spam contributions (e.g., multiple small contributions to inflate `participants`).


An attacker could submit contributions with disproportionately high `pointAmt` values, potentially skewing the genesis event’s scoring or distribution logic, or flood the `participants` array, causing gas issues or unfair outcomes.


**Root Cause**: Insufficient input validation in `participate`, allowing malicious contributions that could disrupt event logic.

## Impact
- **Fund Loss**: Malicious contributions could lead to incorrect token distributions, depriving legitimate participants of their share.
- **Event Disruption**: Skewed `pointAmt` values could manipulate the genesis outcome, favoring attackers.
- **Gas Attacks**: Flooding `participants` with spam contributions could increase gas costs for `onGenesisFailed`, potentially causing DoS.
- **Severity**: High, due to potential financial loss and protocol disruption.


## Recommended Mitigation
1. **Validate `pointAmt`**:
   ```solidity
   require(pointAmt <= maxContributionVirtualAmount, "Excessive point amount");
   ```
2. **Limit Contributions**: Restrict the number of contributions per user or total `participants` size.
3. **Use Safe Math**: Ensure `mapAddrToVirtuals` additions are safe, though Solidity ^0.8.26 mitigates this.
4. **Event Validation**: Add checks to ensure `pointAmt` aligns with `virtualsAmt` (e.g., proportional limits).


## Tools Used
- Manual code review

## References
- [OpenZeppelin AccessControl Documentation](https://docs.openzeppelin.com/contracts/4.x/access-control)
- [Solidity Documentation on Input Validation](https://docs.soliditylang.org/en/v0.8.26/control-structures.html)