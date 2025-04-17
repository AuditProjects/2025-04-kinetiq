// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ========== IMPORTS ========== */

import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IValidatorManager} from "./interfaces/IValidatorManager.sol";
import {IStakingManager} from "./interfaces/IStakingManager.sol";
import {IPauserRegistry} from "./interfaces/IPauserRegistry.sol";
import {IStakingAccountant} from "./interfaces/IStakingAccountant.sol";
import {L1Write} from "./lib/L1Write.sol";
import {KHYPE} from "./KHYPE.sol";

/**
 * @title StakingManager
 * @notice Manages staking, withdrawals, rewards, and validator delegation for the HYPE staking system
 * @dev Implements upgradeable patterns with role-based access control
 */
contract StakingManager is
    IStakingManager,
    Initializable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /* ========== LIBRARIES ========== */

    using Math for uint256;
    using EnumerableSet for EnumerableSet.AddressSet;
    using SafeERC20 for IERC20;

    /* ========== STATE VARIABLES ========== */

    // L1 contract addresses
    address public constant L1_HYPE_CONTRACT = 0x2222222222222222222222222222222222222222;
    L1Write public constant l1Write = L1Write(0x3333333333333333333333333333333333333333);

    // Basis points constant for percentage calculations
    uint256 public constant BASIS_POINTS = 10000; // 100% in basis points

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant SENTINEL_ROLE = keccak256("SENTINEL_ROLE");

    // Core contract references
    IValidatorManager public validatorManager;
    IPauserRegistry public pauserRegistry;
    IStakingAccountant public stakingAccountant;
    KHYPE public kHYPE;
    address public treasury;

    // Token IDs - can be different between mainnet and testnet
    uint64 public HYPE_TOKEN_ID;

    // Global accounting
    uint256 public totalStaked; // Total HYPE staked
    uint256 public totalClaimed; // Total HYPE claimed/withdrawn
    uint256 public totalQueuedWithdrawals; // Total amount of all pending withdrawal requests

    // Buffer management
    // 用户提现可直接从hypeBuffer拿,无需从validator赎回
    uint256 public hypeBuffer; // Current buffer amount
    uint256 public targetBuffer; // Target buffer size

    // Staking parameters
    uint256 public stakingLimit; // Maximum total stake (0 = unlimited)
    uint256 public minStakeAmount; // Minimum stake per call
    uint256 public maxStakeAmount; // Maximum stake per call (0 = unlimited)
    uint256 public withdrawalDelay; // Delay period for withdrawals
    uint256 public unstakeFeeRate; // Fee rate in basis points (10 = 0.1%)

    // Pause flags
    bool public stakingPaused;
    bool public withdrawalPaused;
    bool public whitelistEnabled;

    // User tracking
    mapping(address => uint256) public nextWithdrawalId;

    // Private variables
    uint256 private _cancelledWithdrawalAmount;

    // Private structures
    mapping(address => mapping(uint256 => WithdrawalRequest)) private _withdrawalRequests;
    EnumerableSet.AddressSet private _whitelist;
    // @？ _pendingWithdrawals 直接被删除还能使用吗
    L1Operation[] private _pendingWithdrawals; // UserWithdrawal and RebalanceWithdrawal
    L1Operation[] private _pendingDeposits; // UserDeposit and RebalanceDeposit

    // Separate processing indices
    uint256 private _withdrawalProcessingIndex;
    uint256 private _depositProcessingIndex;

    /* ========== MODIFIERS ========== */

    modifier whenNotPaused() {
        require(!pauserRegistry.isPaused(address(this)), "Contract is paused");
        _;
    }

    modifier whenStakingNotPaused() {
        require(!stakingPaused, "Staking is paused");
        _;
    }

    modifier whenWithdrawalNotPaused() {
        require(!withdrawalPaused, "Withdrawals are paused");
        _;
    }

    /* ========== INITIALIZATION ========== */

    /**
     * @notice Initializes the StakingManager contract
     * @param admin Address to be granted admin role
     * @param operator Address to be granted operator role
     * @param manager Address to be granted manager role
     * @param _pauserRegistry Address of the pauser registry contract
     * @param _kHYPE Address of the kHYPE token contract
     * @param _validatorManager Address of the validator manager contract
     * @param _stakingAccountant Address of the staking accountant contract
     * @param _treasury Address of the treasury contract
     * @param _minStakeAmount Minimum stake amount
     * @param _maxStakeAmount Maximum stake amount (0 = unlimited)
     * @param _stakingLimit Maximum total staking limit (0 = unlimited)
     * @param _hypeTokenId Token ID for HYPE on L1
     */
    function initialize(
        address admin,
        address operator,
        address manager,
        address _pauserRegistry,
        address _kHYPE,
        address _validatorManager,
        address _stakingAccountant,
        address _treasury,
        uint256 _minStakeAmount,
        uint256 _maxStakeAmount,
        uint256 _stakingLimit,
        uint64 _hypeTokenId
    ) public initializer {
        // Validate addresses
        require(_pauserRegistry != address(0), "Invalid pauser registry");
        require(_kHYPE != address(0), "Invalid kHYPE token");
        require(_validatorManager != address(0), "Invalid validator manager");
        require(_stakingAccountant != address(0), "Invalid staking accountant");
        require(admin != address(0), "Invalid admin address");
        require(operator != address(0), "Invalid operator address");
        require(manager != address(0), "Invalid manager address");
        require(_treasury != address(0), "Invalid treasury address");

        // Validate staking parameters
        require(_minStakeAmount > 0, "Invalid min stake amount");
        if (_maxStakeAmount > 0) {
            require(_maxStakeAmount > _minStakeAmount, "Invalid max stake amount");
        }
        if (_stakingLimit > 0) {
            require(_stakingLimit > _maxStakeAmount && _stakingLimit > _minStakeAmount, "Invalid staking limit");
        }

        // Initialize staking parameters
        minStakeAmount = _minStakeAmount;
        maxStakeAmount = _maxStakeAmount;
        stakingLimit = _stakingLimit;

        // Initialize OpenZeppelin contracts
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();

        // Set contract references
        pauserRegistry = IPauserRegistry(_pauserRegistry);
        kHYPE = KHYPE(_kHYPE);
        validatorManager = IValidatorManager(_validatorManager);
        stakingAccountant = IStakingAccountant(_stakingAccountant);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, operator);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(TREASURY_ROLE, _treasury);

        // Set treasury
        treasury = _treasury;
        // Set HYPE token ID
        HYPE_TOKEN_ID = _hypeTokenId;

        // Default setups
        unstakeFeeRate = 10;
        withdrawalDelay = 7 days;
    }

    /* ========== FALLBACK FUNCTIONS ========== */

    /**
     * @notice Fallback function to handle direct ETH transfers
     * @dev Redirects incoming ETH to the stake function
     */
    receive() external payable {
        // Simply call the stake function
        // @q-a 使用合约账户 - ok
        stake();
    }

    /* ========== STAKING FUNCTIONS ========== */

    /**
     * @notice Stakes HYPE tokens and mints kHYPE tokens
     * @dev Can be called directly or via the receive function
     */
    // @entry 质押入口(用户调用)
    function stake() public payable nonReentrant whenNotPaused whenStakingNotPaused {
        // Check whitelist if enabled
        if (whitelistEnabled) {
            require(isWhitelisted(msg.sender), "Address not whitelisted");
        }

        // Validate stake amount
        // 质押数量限制
        require(msg.value >= minStakeAmount, "Stake amount below minimum");
        if (maxStakeAmount > 0) {
            require(msg.value <= maxStakeAmount, "Stake amount above maximum");
        }
        if (stakingLimit > 0) { // 检查
            // Get rewards from ValidatorManager to account for earned rewards
            // This approach uses global rewards but provides a reasonable approximation
            // for this StakingManager's available capacity
            // 获取所有验证者的全局奖励总额
            uint256 rewardsAmount = validatorManager.totalRewards();
            uint256 netStaked = totalStaked + rewardsAmount - totalClaimed; // 净质押总量
            require(netStaked + msg.value <= stakingLimit, "Staking limit reached");
        }
        // 更新 StakingManager 中 totalStaked
        totalStaked += msg.value;

        // Convert HYPE to kHYPE amount using exchange ratio
        // 先计算kHYPE，再进行分配。这样即使部分作为reminder加入buffer也不影响用户得到的 kHYPE
        uint256 kHYPEAmount = stakingAccountant.HYPEToKHYPE(msg.value);

        // Mint kHYPE tokens based on the conversion
        kHYPE.mint(msg.sender, kHYPEAmount);

        _distributeStake(msg.value, OperationType.UserDeposit);
         // 更新 StakingAccountant 中 totalStaked
        stakingAccountant.recordStake(msg.value);

        emit StakeReceived(address(this), msg.sender, msg.value);
    }

    /* ========== WITHDRAWAL FUNCTIONS ========== */
    // 用户执行 提款
    function queueWithdrawal(uint256 kHYPEAmount) external nonReentrant whenNotPaused whenWithdrawalNotPaused {
        // Check whitelist if enabled
        if (whitelistEnabled) {
            require(isWhitelisted(msg.sender), "Address not whitelisted");
        }

        require(kHYPEAmount > 0, "Invalid amount");
        require(kHYPE.balanceOf(msg.sender) >= kHYPEAmount, "Insufficient kHYPE balance");

        uint256 withdrawalId = nextWithdrawalId[msg.sender];

        // Calculate fee in kHYPE using mulDiv for precision
        // kHYPEAmount is in 8 decimals
        uint256 kHYPEFee = msg.sender == treasury ? 0 : Math.mulDiv(kHYPEAmount, unstakeFeeRate, BASIS_POINTS);
        uint256 postFeeKHYPE = kHYPEAmount - kHYPEFee;

        // Convert post-fee kHYPE to HYPE using StakingAccountant
        // Both kHYPE and HYPE are in 8 decimals
        uint256 hypeAmount = stakingAccountant.kHYPEToHYPE(postFeeKHYPE);

        // Lock kHYPE tokens
        // 向合约还 KHYPE
        kHYPE.transferFrom(msg.sender, address(this), kHYPEAmount);

        // Create withdrawal request
        // withdrawal请求入队, 这里是后续提款的依据
        _withdrawalRequests[msg.sender][withdrawalId] = WithdrawalRequest({
            hypeAmount: hypeAmount,
            kHYPEAmount: postFeeKHYPE,
            kHYPEFee: kHYPEFee,
            timestamp: block.timestamp
        });

        nextWithdrawalId[msg.sender]++;
        // 统计待发放的资金
        totalQueuedWithdrawals += hypeAmount;

        // Withdraw from current delegation
        // 当前 stakingManager 对应的 validator(非合约, 验证者地址)
        address currentDelegation = validatorManager.getDelegation(address(this));
        require(currentDelegation != address(0), "No delegation set");
        // 看是否需要从L1 validator提款
        _withdrawFromValidator(currentDelegation, hypeAmount, OperationType.UserWithdrawal);

        emit WithdrawalQueued(address(this), msg.sender, withdrawalId, kHYPEAmount, hypeAmount, kHYPEFee);
    }

    /**
     * @notice Confirms a single withdrawal request
     * @param withdrawalId ID of the withdrawal to confirm
     */
    //
    function confirmWithdrawal(uint256 withdrawalId) external nonReentrant whenNotPaused {
        // 实际提款的 hype 数量
        uint256 amount = _processConfirmation(msg.sender, withdrawalId);
        require(amount > 0, "No valid withdrawal request");
        require(address(this).balance >= amount, "Insufficient contract balance");

        stakingAccountant.recordClaim(amount);

        // Process withdrawal using call instead of transfer
        // @audit-ok DoS，造成缓冲资金hype不够，用户每次无法成功调用 confirmWithdrawal - 协议使然，等待调度资金

        // @q-a reentrancy?能否重入其他函数 - 目前未发现
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }

    function batchConfirmWithdrawals(uint256[] calldata withdrawalIds) external nonReentrant whenNotPaused {
        uint256 totalAmount = 0;

        for (uint256 i = 0; i < withdrawalIds.length; i++) {
            totalAmount += _processConfirmation(msg.sender, withdrawalIds[i]);
        }

        // Process total withdrawal if any valid requests were found
        if (totalAmount > 0) {
            require(address(this).balance >= totalAmount, "Insufficient contract balance");

            stakingAccountant.recordClaim(totalAmount);

            // Process withdrawal using call instead of transfer
            // @q-a reentrancy?  - 目前未发现
            (bool success, ) = payable(msg.sender).call{value: totalAmount}("");
            require(success, "Transfer failed");
        }
    }

    /**
     * @notice Process validator withdrawals requested by ValidatorManager
     * @param validators Array of validator addresses
     * @param amounts Array of amounts to withdraw
     */
     // 从L1进行提款
    function processValidatorWithdrawals(
        address[] calldata validators,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused {
        require(msg.sender == address(validatorManager), "Only ValidatorManager");
        require(validators.length == amounts.length, "Length mismatch");
        require(validators.length > 0, "Empty arrays");

        for (uint256 i = 0; i < validators.length; ) {
            require(amounts[i] > 0, "Invalid amount");

            // Use RebalanceWithdrawal type
            _withdrawFromValidator(validators[i], amounts[i], OperationType.RebalanceWithdrawal);

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Delegate available balance to current validator
     * @param amount Amount to delegate (in 8 decimals)
     */
     // 重新分配质押(入队)
    function processValidatorRedelegation(uint256 amount) external nonReentrant whenNotPaused {
        require(msg.sender == address(validatorManager), "Only ValidatorManager");
        require(amount > 0, "Invalid amount");
        require(address(this).balance >= amount, "Insufficient balance");
        // RebalanceDeposit: 重新 deposit 质押
        _distributeStake(amount, OperationType.RebalanceDeposit);
    }

    /* ========== INTERNAL FUNCTIONS ========== */

    /**
     * @dev Internal function to process a single withdrawal confirmation
     * @param user Address of the user
     * @param withdrawalId ID of the withdrawal
     * @return amount The amount processed, 0 if skipped
     */
    function _processConfirmation(address user, uint256 withdrawalId) internal returns (uint256) {
        WithdrawalRequest memory request = _withdrawalRequests[user][withdrawalId];

        // @audit-m2-ok 若用户请求提现后质押池遭受惩罚，总质押减少，此处应该重新计算
        // Skip if request doesn't exist or delay period not met
        if (request.hypeAmount == 0 || block.timestamp < request.timestamp + withdrawalDelay) {
            return 0;
        }

        uint256 hypeAmount = request.hypeAmount;
        uint256 kHYPEAmount = request.kHYPEAmount;
        uint256 kHYPEFee = request.kHYPEFee;

        // Check kHYPE balances
        require(kHYPE.balanceOf(address(this)) >= kHYPEAmount + kHYPEFee, "Insufficient kHYPE balance");

        // Update state
        totalQueuedWithdrawals -= hypeAmount;
        totalClaimed += hypeAmount;
        delete _withdrawalRequests[user][withdrawalId];

        // Burn kHYPE tokens (excluding fee)
        // 烧掉 kHYPEAmount
        kHYPE.burn(address(this), kHYPEAmount);

        // Transfer fee to treasury
        // 转 treasury手续费 kHYPEFee
        kHYPE.transfer(treasury, kHYPEFee);

        emit WithdrawalConfirmed(user, withdrawalId, hypeAmount);

        return hypeAmount;
    }

    /**
     * @notice Converts amount from 18 decimals to 8 decimals for L1 operations
     * @param amount Amount in 18 decimals
     * @param roundUp Whether to round up (for withdrawals) or down (for deposits)
     * @return truncatedAmount Amount in 8 decimals
     */
    function _convertTo8Decimals(uint256 amount, bool roundUp) internal pure returns (uint256 truncatedAmount) {
        truncatedAmount = amount / 1e10;

        // For withdrawals, round up to ensure users get at least the requested amount
        if (roundUp && amount % 1e10 > 0) {
            truncatedAmount += 1;
        }

        // Add check for uint64 overflow
        require(truncatedAmount <= type(uint64).max, "Amount exceeds uint64 max");

        return truncatedAmount;
    }

    /**
     * @notice Internal function to distribute stake to validators
     * @param amount Amount to stake (in 18 decimals)
     * @param operationType Type of operation
     */
    //
    function _distributeStake(uint256 amount, OperationType operationType) internal {
        // Get the current delegation target
        address validator = validatorManager.getDelegation(address(this));

        // For user deposits, handle buffer first
        if (operationType == OperationType.UserDeposit) { // 存入
            // Check that amount can be cleanly divided into 8 decimals
            // HyperCore 的 HYPE 是 8 decimals
            // HyperEVM 是 18 decimals，所以要做精度处理,保证后续不会丢失精度
            // HyperEVM: 1 ETH (1e18)
            // HyperCore: 1e18 / 1e10 = 1e8 = 1 CoreETH
            require(amount % 1e10 == 0, "Amount must be divisible by 1e10");

            // Handle buffer first
            // memory优化gas
            uint256 currentBuffer = hypeBuffer;
            uint256 target = targetBuffer; // 假设 target = 1 wei
            if (amount > 0 && currentBuffer < target) {
                // @q-a 如何使 target - currentBuffer 这个值留有尾数? 后续 remainder 则会每次存入buffer(薅用户羊毛) - 设置一个极小 targetBuffer
                // @audit-m3-no 若设置一个极小 targetBuffer，计算时会造成小数，随着大量积累,用户会被薅羊毛？
                // - 这种造成小数没什么问题，首选提取兑换了 KHYPE，不管是buffer中的还是totalStaked中的都不会影响 totalStaked，即兑换率
                uint256 bufferSpace = target - currentBuffer;
                // 优先将用户质押的部分资金填入流动性 buffer
                uint256 amountToBuffer = Math.min(amount, bufferSpace);
                hypeBuffer = currentBuffer + amountToBuffer;
                // 质押数量中减去
                amount -= amountToBuffer; // 1e17 - 1 = 0.999...e17

                emit BufferIncreased(amountToBuffer, hypeBuffer);
            }

            // If no amount left after buffer, return
            if (amount == 0) {
                return;
            }

            // Ensure amount after buffer is still divisible by 1e10
            // 剩余的部分若有 尾数, 则这点尾数添加到 hypeBuffer
            // 这里，不管buffer设置多小，如果stake金额尾数为整数，都会将 1e10 放入 buffer
            uint256 remainder = amount % 1e10;  // remainder = 0.999...e10
            if (remainder > 0) {
                // Add the remainder to the buffer
                hypeBuffer += remainder;
                amount -= remainder;   // amount = 0.999...000e17
                /// @dev It will retain those decimals in this contract, providing exit liquidity.

                // If all amount went to buffer, return
                if (amount == 0) {
                    return;
                }
            }

            // For user deposits, move HYPE from EVM to spot balance
            // 1. Move HYPE from EVM to spot balance on L1 by sending directly to L1 address
            // 1. 从 EVM 向 HyperCore 发送可用余额
            // @?. 记录谁的余额? 合约? - 合约自己的
            (bool success, ) = payable(L1_HYPE_CONTRACT).call{value: amount}("");
            require(success, "Failed to send HYPE to L1");

            // 2. Move from spot balance to staking balance using cDeposit
            uint256 truncatedAmount = _convertTo8Decimals(amount, false);
            // 质押准备, 转入 validator staking 池 (发送事件由 Operator 后续操作)
            l1Write.sendCDeposit(uint64(truncatedAmount));

            // 3. Queue the delegation operation (8 decimals)
            // 3. 正式质押，将操作入队
            _queueL1Operation(validator, truncatedAmount, operationType);
        } else if (operationType == OperationType.SpotDeposit) {
            // For spot deposits, first move from spot balance to staking balance
            uint256 truncatedAmount = _convertTo8Decimals(amount, false);
            require(truncatedAmount <= type(uint64).max, "Amount exceeds uint64 max");

            // 1. First move from spot balance to staking balance using cDeposit
            l1Write.sendCDeposit(uint64(truncatedAmount));

            // 2. Queue the delegation operation (8 decimals)
            _queueL1Operation(validator, truncatedAmount, OperationType.RebalanceDeposit);
        } else if (operationType == OperationType.RebalanceDeposit) {
            // For rebalance deposits, just queue the operation
            // Convert to 8 decimals
            uint256 truncatedAmount = _convertTo8Decimals(amount, false);

            // Queue the delegation operation (8 decimals)
            // RebalanceDeposit：直接质押
            _queueL1Operation(validator, truncatedAmount, operationType);
        } else {
            revert("unrecognized operation type");
        }
        emit Delegate(address(this), validator, amount);
    }

    /**
     * @notice Internal function to withdraw from validator
     * @param validator Validator address
     * @param amount Amount to withdraw (in 18 decimals)
     * @param operationType Type of operation (UserWithdrawal or RebalanceWithdrawal)
     */
     // 入队延迟执行
    function _withdrawFromValidator(address validator, uint256 amount, OperationType operationType) internal {
        require(validator != address(0), "Invalid validator address");
        require(amount > 0, "Invalid withdrawal amount");

        // For user withdrawals, try to fulfill from buffer first
        if (operationType == OperationType.UserWithdrawal) {
            // Buffer handling uses 18 decimal precision
            uint256 currentBuffer = hypeBuffer;
            uint256 amountFromBuffer = Math.min(amount, currentBuffer);
            // 如果有缓冲资金
            if (amountFromBuffer > 0) {
                hypeBuffer = currentBuffer - amountFromBuffer;
                amount -= amountFromBuffer;  // amount =  - 1
                emit BufferDecreased(amountFromBuffer, hypeBuffer);
            }

            // If fully fulfilled from buffer, return
            if (amount == 0) {
                return;
            }
        } else if (operationType == OperationType.RebalanceWithdrawal) {
            // For rebalance withdrawals, we don't need to check the buffer
            // Just continue with the withdrawal
        } else {
            revert("unrecognized operation type");
        }

        // Convert to 8 decimals, rounding up for withdrawals
        uint256 truncatedAmount = _convertTo8Decimals(amount, true);

        // Queue the withdrawal operation
        _queueL1Operation(validator, truncatedAmount, operationType);

        emit ValidatorWithdrawal(address(this), validator, amount);
    }

    /**
     * @notice Queue multiple L1 operations
     * @param validators Array of validator addresses
     * @param amounts Array of amounts to process (in 18 decimals)
     * @param operationTypes Array of operation types
     * @dev Only callable by OPERATOR_ROLE
     */
    function queueL1Operations(
        address[] calldata validators,
        uint256[] calldata amounts,
        OperationType[] calldata operationTypes
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        require(validators.length == amounts.length, "Length mismatch");
        require(validators.length == operationTypes.length, "Length mismatch");
        require(validators.length > 0, "Empty arrays");

        // Queue each operation directly
        for (uint256 i = 0; i < validators.length; ) {
            // Check that validator is active for deposit operations
            if (
                operationTypes[i] == OperationType.UserDeposit ||
                operationTypes[i] == OperationType.RebalanceDeposit ||
                operationTypes[i] == OperationType.SpotDeposit
            ) {
                require(validatorManager.validatorActiveState(validators[i]), "Validator not active");
            } // @q-a 如果不是deposit就直接跳过检查了？ - 用户提现 即使 validator 已被关停也允许操作, 否则资金会卡住

            // Determine if this is a withdrawal for rounding purposes
            bool isWithdrawal = operationTypes[i] == OperationType.UserWithdrawal ||
                operationTypes[i] == OperationType.RebalanceWithdrawal;

            // Convert to 8 decimals with appropriate rounding
            uint256 truncatedAmount = _convertTo8Decimals(amounts[i], isWithdrawal);

            // Queue the L1 operation
            _queueL1Operation(validators[i], truncatedAmount, operationTypes[i]);

            unchecked {
                ++i;
            }
        }

        emit L1OperationsQueued(validators, amounts, operationTypes);
    }

    /**
     * @notice Internal function to queue an L1 operation
     * @param validator Validator address
     * @param amount Amount for the operation (in 8 decimals)
     * @param operationType Type of operation
     */
    function _queueL1Operation(address validator, uint256 amount, OperationType operationType) internal {
        // Create the L1 operation
        L1Operation memory operation = L1Operation({
            validator: validator,
            amount: amount,
            operationType: operationType
        });

        // Add to the appropriate queue based on operation type
        bool isWithdrawal = operationType == OperationType.UserWithdrawal ||
            operationType == OperationType.RebalanceWithdrawal;

        if (isWithdrawal) {
            _pendingWithdrawals.push(operation);
        } else {
            _pendingDeposits.push(operation);
        }

        emit L1DelegationQueued(address(this), validator, amount, operationType);
    }

    /**
     * @notice Process pending L1 operations in batch with a limit
     * @param batchSize Maximum number of operations to process in this transaction (0 for all)
     * @dev Only callable by operator role
     */
    function processL1Operations(uint256 batchSize) public onlyRole(OPERATOR_ROLE) whenNotPaused {
        uint256 withdrawalsLength = _pendingWithdrawals.length;
        uint256 depositsLength = _pendingDeposits.length;

        // Check if there are any operations to process
        require(
            withdrawalsLength > _withdrawalProcessingIndex || depositsLength > _depositProcessingIndex,
            "No pending operations"
        );

        uint256 processedCount = 0;

        // If batchSize is 0, process all operations
        if (batchSize == 0) {
            // Process all withdrawals
            uint256 withdrawalsProcessed = _processL1Withdrawals(0);
            processedCount += withdrawalsProcessed;

            // Process all deposits
            uint256 depositsProcessed = _processL1Deposits(0);
            processedCount += depositsProcessed;
        } else {
            // Process withdrawals first with priority
            uint256 withdrawalsProcessed = _processL1Withdrawals(batchSize);
            processedCount += withdrawalsProcessed;

            // If we have remaining capacity, process deposits
            if (withdrawalsProcessed < batchSize) {
                uint256 depositBatchSize = batchSize - withdrawalsProcessed;
                uint256 depositsProcessed = _processL1Deposits(depositBatchSize);
                processedCount += depositsProcessed;
            }
        }

        emit L1OperationsBatchProcessed(
            processedCount,
            (_pendingWithdrawals.length - _withdrawalProcessingIndex) +
                (_pendingDeposits.length - _depositProcessingIndex)
        );
    }

    /**
     * @dev Internal function to process withdrawal operations
     * @param batchSize Maximum number of operations to process (0 for unlimited)
     * @return uint256 Number of operations processed
     */
     // @?. 从L1提款
    function _processL1Withdrawals(uint256 batchSize) internal returns (uint256) {
        uint256 length = _pendingWithdrawals.length;
        if (length <= _withdrawalProcessingIndex) {
            return 0;
        }

        // Calculate how many operations we can process
        uint256 endIndex = _withdrawalProcessingIndex + batchSize;
        if (endIndex > length || batchSize == 0) {
            endIndex = length;
        }

        uint256 processedCount = 0;

        // Process withdrawals
        for (uint256 i = _withdrawalProcessingIndex; i < endIndex; i++) {
            L1Operation memory op = _pendingWithdrawals[i];
            require(op.amount <= type(uint64).max, "Amount exceeds uint64 max");

            // Send withdrawal to L1 (8 decimals)
            // 解质押：isUndelegate true， 资金返回本合约
            l1Write.sendTokenDelegate(op.validator, uint64(op.amount), true);

            // Only call sendCWithdrawal for user withdrawals
            //
            if (op.operationType == OperationType.UserWithdrawal) {
                l1Write.sendCWithdrawal(uint64(op.amount));
            }

            emit L1DelegationProcessed(address(this), op.validator, op.amount, op.operationType);
            processedCount++;
        }

        // Update the processing index
        _withdrawalProcessingIndex = endIndex;

        // If we've processed all operations, reset the queue
        if (_withdrawalProcessingIndex == length) {
            delete _pendingWithdrawals;
            _withdrawalProcessingIndex = 0;
        }

        return processedCount;
    }

    /**
     * @dev Internal function to process deposit operations
     * @param batchSize Maximum number of operations to process (0 for unlimited)
     * @return uint256 Number of operations processed
     */
    function _processL1Deposits(uint256 batchSize) internal returns (uint256) {
        uint256 length = _pendingDeposits.length;
        if (length <= _depositProcessingIndex) {
            return 0;
        }

        // Calculate how many operations we can process
        uint256 endIndex = _depositProcessingIndex + batchSize;
        if (endIndex > length || batchSize == 0) {
            endIndex = length;
        }

        uint256 processedCount = 0;

        // Process deposits
        for (uint256 i = _depositProcessingIndex; i < endIndex; i++) {
            L1Operation memory op = _pendingDeposits[i];
            require(op.amount <= type(uint64).max, "Amount exceeds uint64 max"); // @reported modified check uint64 max

            // Send delegation to L1 (8 decimals)
            // 正式质押
            l1Write.sendTokenDelegate(op.validator, uint64(op.amount), false);

            emit L1DelegationProcessed(address(this), op.validator, op.amount, op.operationType);
            processedCount++;
        }

        // Update the processing index
        _depositProcessingIndex = endIndex;

        // If we've processed all operations, reset the queue
        if (_depositProcessingIndex == length) {
            delete _pendingDeposits;
            _depositProcessingIndex = 0;
        }

        return processedCount;
    }

    // Keep the original function for backward compatibility
    // @q-a 调用processL1Operations - yes
    function processL1Operations() external {
        processL1Operations(0); // Process all operations
    }

    /* ========== VIEW FUNCTIONS ========== */

    /// @notice Gets withdrawal request details for a user
    function withdrawalRequests(address user, uint256 id) external view returns (WithdrawalRequest memory) {
        return _withdrawalRequests[user][id];
    }

    /* ========== ADMIN FUNCTIONS ========== */

    function setTargetBuffer(uint256 newTargetBuffer) external onlyRole(MANAGER_ROLE) {
        targetBuffer = newTargetBuffer;
        emit TargetBufferUpdated(newTargetBuffer);
    }

    function setStakingLimit(uint256 newStakingLimit) external onlyRole(MANAGER_ROLE) {
        if (newStakingLimit > 0) {
            require(newStakingLimit > maxStakeAmount && newStakingLimit > minStakeAmount, "Invalid staking limit");
        }
        stakingLimit = newStakingLimit;
        emit StakingLimitUpdated(newStakingLimit);
    }

    /**
     * @notice Set minimum stake amount
     * @param newMinStakeAmount New minimum stake amount
     * @dev Only callable by MANAGER_ROLE
     */
    function setMinStakeAmount(uint256 newMinStakeAmount) external onlyRole(MANAGER_ROLE) {
        require(newMinStakeAmount > 0, "Invalid min stake amount");
        require(newMinStakeAmount % 1e10 == 0, "Amount must be divisible by 1e10");

        minStakeAmount = newMinStakeAmount;
        emit MinStakeAmountUpdated(newMinStakeAmount);
    }

    function setMaxStakeAmount(uint256 newMaxStakeAmount) external onlyRole(MANAGER_ROLE) {
        if (newMaxStakeAmount > 0) {
            require(newMaxStakeAmount > minStakeAmount, "Max stake must be greater than min");
        }
        if (stakingLimit > 0) {
            require(newMaxStakeAmount <= stakingLimit, "Max stake must be less than limit");
        }
        maxStakeAmount = newMaxStakeAmount;
        emit MaxStakeAmountUpdated(newMaxStakeAmount);
    }

    /**
     * @notice Set withdrawal delay period
     * @param newDelay New delay period in seconds
     */
    function setWithdrawalDelay(uint256 newDelay) external onlyRole(MANAGER_ROLE) {
        withdrawalDelay = newDelay;
        emit WithdrawalDelayUpdated(newDelay);
    }

    /**
     * @notice Enable whitelist for staking
     */
    function enableWhitelist() external onlyRole(MANAGER_ROLE) {
        whitelistEnabled = true;
        emit WhitelistEnabled();
    }

    /**
     * @notice Disable whitelist for staking
     */
    function disableWhitelist() external onlyRole(MANAGER_ROLE) {
        whitelistEnabled = false;
        emit WhitelistDisabled();
    }

    /**
     * @notice Add addresses to whitelist
     * @param accounts Array of addresses to whitelist
     */
    function addToWhitelist(address[] calldata accounts) external onlyRole(MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            require(accounts[i] != address(0), "Invalid address");
            _whitelist.add(accounts[i]);
            emit AddressWhitelisted(accounts[i]);
        }
    }

    /**
     * @notice Remove multiple accounts from the whitelist
     * @param accounts Array of addresses to remove from whitelist
     * @dev Only callable by MANAGER_ROLE
     */
    function removeFromWhitelist(address[] calldata accounts) external onlyRole(MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            // Check if the account is actually in the whitelist before emitting event
            bool removed = _whitelist.remove(accounts[i]);

            // Only emit the event if the account was actually removed
            if (removed) {
                emit AddressRemovedFromWhitelist(accounts[i]);
            }
            // Silently skip accounts that weren't in the whitelist
        }
    }

    /**
     * @notice Check if address is whitelisted
     * @param account Address to check
     * @return bool True if address is whitelisted
     */
    function isWhitelisted(address account) public view returns (bool) {
        return _whitelist.contains(account);
    }

    /**
     * @notice Get number of whitelisted addresses
     * @return uint256 Number of whitelisted addresses
     */
    function whitelistLength() external view returns (uint256) {
        return _whitelist.length();
    }

    /**
     * @notice Pause staking operations
     */
    function pauseStaking() external onlyRole(MANAGER_ROLE) {
        stakingPaused = true;
        emit StakingPaused(msg.sender);
    }

    /**
     * @notice Unpause staking operations
     */
    function unpauseStaking() external onlyRole(MANAGER_ROLE) {
        stakingPaused = false;
        emit StakingUnpaused(msg.sender);
    }

    /**
     * @notice Pause withdrawal operations
     */
    function pauseWithdrawal() external onlyRole(MANAGER_ROLE) {
        withdrawalPaused = true;
        emit WithdrawalPaused(msg.sender);
    }

    /**
     * @notice Unpause withdrawal operations
     */
    function unpauseWithdrawal() external onlyRole(MANAGER_ROLE) {
        withdrawalPaused = false;
        emit WithdrawalUnpaused(msg.sender);
    }

    /**
     * @notice Cancel a withdrawal request (manager only)
     * @param user Address of the user who made the withdrawal request
     * @param withdrawalId ID of the withdrawal to cancel
     */
     // StakingManager层面取消某用户的提款请求withdrawalId
     // @audit-m2-ok 补充 虽然可以在StakingManager层面取消提款，但是ValidatorManager层面依然在pending状态
    function cancelWithdrawal(address user, uint256 withdrawalId) external onlyRole(MANAGER_ROLE) whenNotPaused {
        WithdrawalRequest storage request = _withdrawalRequests[user][withdrawalId];
        require(request.hypeAmount > 0, "No such withdrawal request");
        // 这里 hypeAmount 是请求提款时，根据兑换率算得的
        uint256 hypeAmount = request.hypeAmount;
        uint256 kHYPEAmount = request.kHYPEAmount;
        uint256 kHYPEFee = request.kHYPEFee;

        // Check kHYPE balances
        require(kHYPE.balanceOf(address(this)) >= kHYPEAmount + kHYPEFee, "Insufficient kHYPE balance");

        // Clear the withdrawal request
        delete _withdrawalRequests[user][withdrawalId];
        totalQueuedWithdrawals -= hypeAmount;

        // Return kHYPE tokens to user (including fees)
        // 将 kHYPE 还给用户
        kHYPE.transfer(user, kHYPEAmount + kHYPEFee);

        // Track cancelled amount for future redelegation
        _cancelledWithdrawalAmount += hypeAmount;

        emit WithdrawalCancelled(user, withdrawalId, hypeAmount, _cancelledWithdrawalAmount);
    }

    /**
     * @notice Redelegate withdrawn HYPE that was previously cancelled
     */
     // 取消提款的资金 进入合约，为 _cancelledWithdrawalAmount
     // 重新分配质押 _cancelledWithdrawalAmount 的
    function redelegateWithdrawnHYPE() external onlyRole(MANAGER_ROLE) whenNotPaused {
        require(_cancelledWithdrawalAmount > 0, "No cancelled withdrawals");
        require(address(this).balance >= _cancelledWithdrawalAmount, "Insufficient HYPE balance");

        uint256 amount = _cancelledWithdrawalAmount;
        _cancelledWithdrawalAmount = 0;

        // Delegate to current validator using the SpotDeposit operation type
        // @q 一定会有 _cancelledWithdrawalAmount 的 hype可以进行deposit吗
        _distributeStake(amount, OperationType.SpotDeposit);

        emit WithdrawalRedelegated(amount);
    }

    /**
     * @notice Reset the L1 operations queue in case of emergency
     * @dev Only callable by admin role
     */
    // bool public isFrozen;
    // modifier checkIsFrozen() {
    //     if (!isFrozen) {
    //         _;
    //     }
    // }

    function resetL1OperationsQueue() external onlyRole(MANAGER_ROLE) {
        isFrozen = true;
        uint256 withdrawalsLength = _pendingWithdrawals.length;
        uint256 depositsLength = _pendingDeposits.length;
        // @q-a 意外重置，会对全局产生什么影响 - 下面影响
        // @audit-m4-ok 用户提款，已将KHYPE还给合约，但 _pendingWithdrawals 被删，资金无端损失
        // - 不一定要删除全部，
        // - 可加入状态，
        delete _pendingWithdrawals;
        delete _pendingDeposits;
        _withdrawalProcessingIndex = 0;
        _depositProcessingIndex = 0;

        emit L1OperationsQueueReset(withdrawalsLength + depositsLength);
    }

    /**
     * @notice Update unstake fee rate
     * @param newRate New fee rate in basis points
     */
    function setUnstakeFeeRate(uint256 newRate) external onlyRole(MANAGER_ROLE) {
        require(newRate <= 1000, "Fee rate too high"); // Max 10%
        unstakeFeeRate = newRate;
        emit UnstakeFeeRateUpdated(newRate);
    }

    // Add treasury setter
    function setTreasury(address newTreasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTreasury != address(0), "Invalid treasury address");
        address oldTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }

    // Function to move funds from spot balance back to EVM after delay, it can be a public method
    // @?
    function withdrawFromSpot(uint64 amount) external onlyRole(OPERATOR_ROLE) {
        l1Write.sendSpot(L1_HYPE_CONTRACT, HYPE_TOKEN_ID, amount);
        emit SpotWithdrawn(amount);
    }

    /* ========== TREASURY FUNCTIONS ========== */

    /**
     * @notice Withdraw any token from Spot balance, mainly resuce L1 tokens or potential token airdrops
     * @param tokenId The token ID to withdraw
     * @param amount The amount to withdraw
     * @dev Only callable by TREASURY_ROLE
     */
    function withdrawTokenFromSpot(uint64 tokenId, uint64 amount) external onlyRole(TREASURY_ROLE) whenNotPaused {
        require(amount > 0, "Invalid amount");

        // Ensure we're not withdrawing HYPE token if it's needed for staking
        if (tokenId == HYPE_TOKEN_ID) {
            return;
        }

        // Send the token from spot balance to the recipient
        l1Write.sendSpot(treasury, tokenId, amount);

        emit TokenWithdrawnFromSpot(tokenId, amount, treasury);
    }

    /**
     * @notice Rescue tokens accidentally sent to this contract, or potential token airdrops on HyperEVM
     * @param token The token address (use address(0) for native tokens)
     * @param amount The amount to rescue
     * @dev Only callable by TREASURY_ROLE
     * @dev Cannot be used to withdraw kHYPE or staked HYPE
     */
    function rescueToken(address token, uint256 amount) external onlyRole(TREASURY_ROLE) whenNotPaused {
        require(amount > 0, "Invalid amount");

        // Prevent withdrawing HYPE & kHYPE tokens which are needed for the protocol
        require(token != address(kHYPE), "Cannot withdraw kHYPE or HYPE");

        // For ERC20 tokens - use safeTransfer instead of transfer
        IERC20(token).safeTransfer(treasury, amount);

        emit TokenRescued(token, amount, treasury);
    }

    /**
     * @notice Execute an emergency withdrawal immediately
     * @param validator Address of the validator
     * @param amount Amount to withdraw (in 18 decimals)
     * @dev Only callable by SENTINEL_ROLE
     */
    function executeEmergencyWithdrawal(
        address validator,
        uint256 amount
    ) external nonReentrant whenNotPaused onlyRole(SENTINEL_ROLE) {
        require(validator != address(0), "Invalid validator address");
        require(amount > 0, "Invalid withdrawal amount");

        // Convert to 8 decimals with rounding down (since it's a withdrawal)
        uint256 truncatedAmount = _convertTo8Decimals(amount, true);
        require(truncatedAmount <= type(uint64).max, "Amount exceeds uint64 max");

        // Execute the withdrawal directly
        l1Write.sendTokenDelegate(validator, uint64(truncatedAmount), true);

        // This is a rebalance withdrawal, so funds stay in the system
        emit EmergencyWithdrawalExecuted(validator, amount);
    }
}
