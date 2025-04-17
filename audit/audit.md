
# QA

# [01] A single validator’s reward or slashing affects the global HYPE to kHYPE exchange rate

The current implementation uses a global accounting mechanism in _getExchangeRatio():

https://github.com/code-423n4/2025-04-kinetiq/blob/7f29c917c09341672e73be2f7917edf920ea2adb/src/StakingAccountant.sol#L216


```solidity
uint256 totalHYPE = totalStaked + rewardsAmount - totalClaimed - slashingAmount;
```

This formula sums up all rewards and all slashing across every validator, meaning that even a single validator’s performance, whether good or bad, can affect the exchange rate for everyone.

## Impact
1.	Unfair exposure – Users who stake with good validators may still be affected by bad ones.
2.	Arbitrage risk – Users can monitor L1 validator events and front-run withdrawals to avoid losses.
3.	System fragility – A slashing on one validator impacts the entire protocol’s exchange rate, affecting everyone.


## Proof of Concept
Here’s a simple example to help illustrate the issue:
1.	Validator A is slashed by 100 HYPE.
2.	User X is staking only with Validator B, who had no issues.
3.	But because the global exchange rate drops, X’s kHYPE loses value too.
4.	User Y, who acts quickly, confirms their withdrawal and gets full value.
5.	User X, who waits, may get less or fail due to low contract balance.


## Recommended Mitigation Steps
Consider isolating reward and slashing tracking per validator or introducing a weighting mechanism, so individual validator events do not distort the global ratio.



# [02] Users may front run validator events to profit unfairly

https://github.com/code-423n4/2025-04-kinetiq/blob/7f29c917c09341672e73be2f7917edf920ea2adb/src/ValidatorManager.sol#L427-L438

https://github.com/code-423n4/2025-04-kinetiq/blob/7f29c917c09341672e73be2f7917edf920ea2adb/src/ValidatorManager.sol#L409-L420


Reward and slashing events update both the validator-specific and global totals. It can only be called by an address with the `ORACLE_MANAGER_ROLE`, which is typically an off-chain oracle or automation service that monitors validator activity on L1.

However, this design creates a potential front-running opportunity. Since `reportRewardEvent` (and similarly, `reportSlashingEvent`) directly impacts the global HYPE/kHYPE exchange rate, users can monitor pending reward or slashing updates and time their staking or withdrawal actions to maximize personal gain at the expense of others.

## Impact
This creates a strong MEV opportunity and puts regular users who cannot monitor validator behavior at a disadvantage。


## Proof of Concept
Here’s one possible scenario to illustrate the issue:

- A validator is about to be slashed for 10,000 HYPE
- User A detects this off-chain and quickly calls confirmWithdrawal()
- User A gets full value based on the old exchange rate
- The slashing is reported, the exchange rate drops
- User A stakes again and mints more kHYPE than normal for the same HYPE

## Recommended Mitigation Steps
Consider delaying reward and slashing reporting effect by 1 epoch window so exchange rate cannot be exploited in real time.


---

# Title * M4
`resetL1OperationsQueue` allows deletion of all pending operations and may cause loss of user funds


# Links to affected code *

# Vulnerability details *
## Finding description and impact

The `resetL1OperationsQueue` function allows the manager delete both `_pendingDeposits` and `_pendingWithdrawals`, resetting all in progress operations. This is especially dangerous in the case of pending withdrawals, where users have already locked their `kHYPE` by calling `queueWithdrawal`, but the actual HYPE transfer hasn’t occurred yet.

Once the queue is cleared, the user’s withdrawal request is silently discarded, while their `kHYPE` is already deducted. This means the user loses access to both tokens!

Since this affects all users in the queue at once and is triggered by a single call, it undermines protocol credibility and can result in massive user distrust.

## Recommended mitigation steps
1. Consider adding a freeze flag to prevent accidental deletion of queue data, even in emergency situations where the protocol breaks down, and retain historical tracking data to support recovery later.
2. Emit detailed events before deletion so off-chain systems can reconstruct lost state if needed.


For example, add an `isFrozen` flag:

```diff
+   bool public isFrozen;
+   modifier checkIsFrozen() {
+       if (!isFrozen) {
+           _;
+       }
+   }

    function resetL1OperationsQueue() external onlyRole(MANAGER_ROLE) {
+       isFrozen = true;
-       uint256 withdrawalsLength = _pendingWithdrawals.length;
-       uint256 depositsLength = _pendingDeposits.length;

-       delete _pendingWithdrawals;
-       delete _pendingDeposits;
-       _withdrawalProcessingIndex = 0;
-       _depositProcessingIndex = 0;

-       emit L1OperationsQueueReset(withdrawalsLength + depositsLength);
    }
```

Add a modifier to functions that operate on pending state:

```diff
- function queueWithdrawal(uint256 kHYPEAmount) external nonReentrant whenNotPaused whenWithdrawalNotPaused {
+ function queueWithdrawal(uint256 kHYPEAmount) external nonReentrant whenNotPaused whenWithdrawalNotPaused checkIsFrozen {

- function confirmWithdrawal(uint256 withdrawalId) external nonReentrant whenNotPaused {
+ function confirmWithdrawal(uint256 withdrawalId) external nonReentrant whenNotPaused checkIsFrozen{

```
This approach enables flexible control and ensures state is preserved.

# Proof of Concept (PoC) (optional)
Let’s consider the following scenario:

1. User stakes 1 ether worth of `HYPE`
2. User calls queueWithdrawal to request a withdrawal
3. Manager calls `resetL1OperationsQueue`
4. User loses both `HYPE` and `kHYPE`

Below is the test:

- Add test in `test/StakingManager.t.sol`
- run with: `forge test --mt test_ResetL1OperationsQueue -v`

```solidity
    function test_ResetL1OperationsQueue() public {
        uint256 stakeAmount = 1 ether;
        vm.startPrank(manager);
        validatorManager.activateValidator(validator);
        validatorManager.setDelegation(address(stakingManager), validator);
        vm.stopPrank();

        vm.deal(user, stakeAmount);
        // Step 1: User stakes 1 ether worth of HYPE
        vm.startPrank(user);
        stakingManager.stake{value: stakeAmount}();

        // Step 2: User queues a withdrawal
        kHYPE.approve(address(stakingManager), stakeAmount);
        stakingManager.queueWithdrawal(stakeAmount);
        vm.stopPrank();
        // Step 3: Manager calls resetL1OperationsQueue
        vm.prank(manager);
        stakingManager.resetL1OperationsQueue();
        // Step 4:  User loses both HYPE and kHYPE(confirmWithdrawal can never succeed)
        assertEq(kHYPE.balanceOf(user), 0);
        assertEq(address(user).balance, 0);
    }
```

Expected result: User’s balance of both `HYPE` and `kHYPE` becomes 0.


~~# Title * M3~~
small buffer causes part of user’s stakestake amount to be trapped

# Links to affected code *

# Vulnerability details *
## Finding description and impact
in StakingManager::_distributeStake, when a user stakes HYPE, the contract first tries to top up the internal buffer before sending the remaining funds to the validator. After that, it checks whether the remaining amount is divisible by 1e10 (to match 8 decimals used by HyperCore).

If the buffer is nearly full and only a small amount (like 1 wei) is needed to fill it, the leftover amount after that may not be divisible by 1e10. In that case, the code adds this small remainder into the buffer again, and the actual amount be reduce 1e10 . As a result, the portion of the user’s stake never gets delegated to a validator and stays stuck in the contract.


when users withdraw by queueWithdrawal, _withdrawFromValidator use the buffer HYPE,
In the same way, again, it creates a decimal point problem, and again loss this portion HYPE

As time goes on, more and more HYPE gets stuck

result users HYPE loss and stuck into StakingManager contract,
to users unfair
to protocal ,insufficient utilization of funds, these HYPE not deposit to validator

## Recommended mitigation steps

# Proof of Concept (PoC) (optional)




---


# Title * M2

Validator slashing gives early `confirmWithdrawal` users an unfair advantage

# Links to affected code *


# Vulnerability details *
## Finding description and impact

In the Kinetiq protocol, user withdrawals are completed in two steps: `queueWithdrawal` and `confirmWithdrawal`.
When a user queues a withdrawal, the HYPE amount is fixed and recorded.

However, the actual withdrawable balance from the validator may change afterward, especially if the validator gets slashed on the L1 side.

Since `confirmWithdrawal` internally calls `_processConfirmation` and always uses the `hypeAmount` that was recorded at the time of `queueWithdrawal`, it doesn’t reflect the validator’s latest balance.

As a result, early users who confirm their withdrawal quickly are more likely to receive the full amount.

But later users might fail because the contract balance is no longer enough. This creates an unfair situation where earlier users avoid the loss entirely, while later users bear the full impact.

## Recommended mitigation steps

Consider designing a mechanism to distribute losses more fairly among all affected users.

# Proof of Concept (PoC) (optional)

This issue can be reproduced with a test case like the following:
1.	Both `UserA` and UserB stake `1 ether`, then call `queueWithdrawal`(recording a hypeAmount of `0.999e18`).
2.	Before either confirms, simulate a validator slashing event -> now `StakingManager` only holds `1.5 ether`.
3.	`UserA` calls `confirmWithdrawal` and successfully withdraws `0.999e18`.
4.	`UserB` then tries the same but it reverts due to insufficient balance.

Here is a coded PoC that demonstrates the issue described above:

1. Add the test to `test/StakingManager.t.sol`
2. Run the test with the command: `forge test --mt test_ConfirmWithdrawal_Fail -v`

```solidity
   function test_ConfirmWithdrawal_Fail() public {
        uint256 stakeAmount  = 1 ether;
        address userA = makeAddr("userA");
        address userB = makeAddr("userB");

        address[] memory users = new address[](2);
        users[0] = userA;
        users[1] = userB;

        // Setup validatorManager and stakingManager
        vm.startPrank(manager);
        validatorManager.activateValidator(validator);
        validatorManager.setDelegation(address(stakingManager), validator);
        stakingManager.setWithdrawalDelay(0);
        vm.stopPrank();

        uint256 withdrawalId = 0;
        // Step 1: UserA and UserB stake and queue withdrawal
        for (uint8 i = 0; i < users.length; i++) {
            address _user = users[i];
            vm.deal(_user, stakeAmount);

            vm.startPrank(_user);
            // Stake
            stakingManager.stake{value: stakeAmount}();

            // Withdrawal
            kHYPE.approve(address(stakingManager), stakeAmount);
            stakingManager.queueWithdrawal(stakeAmount);
            vm.stopPrank();
            // Check that hypeAmount recorded is 0.999e18
            StakingManager.WithdrawalRequest memory request = stakingManager.withdrawalRequests(_user, withdrawalId);
            assertEq(request.hypeAmount, 0.999e18);
        }

        // Step 2: Simulate L1 slashing happens before confirmation
        // After slashing, StakingManager only has 1.5e18 HYPE left
        vm.deal(address(stakingManager), 1.5e18);

        // Step3. UserA confirms withdrawal of 0.999e18 -> succeeds
        vm.prank(userA);
        stakingManager.confirmWithdrawal(withdrawalId);

        // Step4. UserB confirms withdrawal of 0.999e18 -> reverts
        vm.prank(userB);
        vm.expectRevert("Insufficient contract balance");
        stakingManager.confirmWithdrawal(withdrawalId);
    }
```
An expectRevert is triggered for `UserB`, since the contract balance cannot cover the requested amount.





# Title * M1

Misused `rebalanceWithdrawal` can lead to DoS of validator operations

# Links to affected code *


# Vulnerability details *
## Finding description and impact

In the Kinetiq protocol, which operates across HyperEVM and HyperCore, validator rebalancing happens in two stages. First, the `rebalanceWithdrawal` is called to queue a withdrawal operation and mark the validator as "pending" using `_validatorsWithPendingRebalance`. Then later, `closeRebalanceRequests` is called to perform redelegation, assuming the withdrawal has been executed successfully on the L1 (HyperCore) side. Notice that once the validator is added to `_validatorsWithPendingRebalance`, only `closeRebalanceRequests` can remove it, as shown in the code below.

```solidity
    function _addRebalanceRequest(address staking, address validator, uint256 withdrawalAmount) internal {
@>      require(!_validatorsWithPendingRebalance.contains(validator), "Validator has pending rebalance");
        require(withdrawalAmount > 0, "Invalid withdrawal amount");

        (bool exists /* uint256 index */, ) = _validatorIndexes.tryGet(validator);
        require(exists, "Validator does not exist");

        validatorRebalanceRequests[validator] = RebalanceRequest({
            staking: staking,
            validator: validator,
            amount: withdrawalAmount
        });
@>      _validatorsWithPendingRebalance.add(validator);

        emit RebalanceRequestAdded(validator, withdrawalAmount);
    }
```

```solidity
    function closeRebalanceRequests(
        address stakingManager,
        address[] calldata validators
    ) external whenNotPaused nonReentrant onlyRole(MANAGER_ROLE) {
        require(_validatorsWithPendingRebalance.length() > 0, "No pending requests");
        require(validators.length > 0, "Empty array");

        uint256 totalAmount = 0;

        for (uint256 i = 0; i < validators.length; ) {
            address validator = validators[i];
            require(_validatorsWithPendingRebalance.contains(validator), "No pending request");

            // Add amount to total for redelegation
            RebalanceRequest memory request = validatorRebalanceRequests[validator];
            require(request.staking == stakingManager, "Invalid staking manager for rebalance");

            totalAmount += request.amount;

            // Clear the rebalance request
            delete validatorRebalanceRequests[validator];
@>          _validatorsWithPendingRebalance.remove(validator);

            emit RebalanceRequestClosed(validator, request.amount);

            unchecked {
                ++i;
            }
        }

        // Trigger redelegation through StakingManager if there's an amount to delegate
        if (totalAmount > 0) {
            IStakingManager(stakingManager).processValidatorRedelegation(totalAmount);
        }
    }
```

So if `rebalanceWithdrawal` is used with a request that can never work, for example, the manager submits an invalid or too large `withdrawalAmount`, the contract still accepts it and marks the validator as pending.

Unfortunately, `closeRebalanceRequests` might fail every time(as mentioned earlier). The validator gets stuck in the "pending" state forever, resulting in a Denial of Service.


## Recommended mitigation steps
Add a `cancelRebalanceRequest` function that only the manager can call, so they can manually clear a validator that’s stuck in the pending state.


# Proof of Concept (PoC) (optional)

Assume that in `rebalanceWithdrawal`, the manager submits a withdrawal amount of 200 for a specific validator, but the corresponding stakingManager only has a balance of `100` and will never reach `200`.
In this case, any call to `closeRebalanceRequests` will always revert and can never succeed, effectively locking the validator in a permanent pending state.

Add the following test case to `ValidatorManager.t.sol`.

```solidity
function test_RebalanceWithdrawal_DoS() public {
        vm.startPrank(manager);
        validatorManager.activateValidator(validator1);
        validatorManager.activateValidator(validator2);
        vm.stopPrank();

        vm.prank(address(oracleManager));
        validatorManager.updateValidatorPerformance(validator1, 100 ether, 8000, 7500, 9000, 8500);

        address[] memory validators = new address[](1);
        validators[0] = validator1;
        uint256[] memory amounts = new uint256[](1);
        // if the stakingManager balance never reaches 200
        amounts[0] = 200 ether;

        // Setup StakingManager balance for redelegation
        vm.deal(address(stakingManager), 100 ether);

        vm.startPrank(manager);
        // Step 1. rebalanceWithdrawal is executed successfully, and the validator enters the pending state
        validatorManager.rebalanceWithdrawal(address(stakingManager), validators, amounts);

        validatorManager.setDelegation(address(stakingManager), validator2);

        // Step 2. closeRebalanceRequests can never be executed successfully
        vm.expectRevert("Insufficient balance");
        validatorManager.closeRebalanceRequests(address(stakingManager), validators);
        vm.stopPrank();

        assertTrue(validatorManager.hasPendingRebalance(validator1));
    }
```

And run it using the following command:

```
forge test --mt test_RebalanceWithdrawal_DoS  -v
```

The logs show that:

```
Ran 1 test for test/ValidatorManager.t.sol:ValidatorManagerTest
[PASS] test_RebalanceWithdrawal_DoS() (gas: 867992)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.49ms (234.29µs CPU time)

Ran 1 test suite in 110.08ms (2.49ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```