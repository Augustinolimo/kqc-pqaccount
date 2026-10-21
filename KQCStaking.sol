// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

interface IFeeDiscount {
    function feeDiscountBps(address user) external view returns (uint256);
}

/**
 * @title KQCStaking
 * @notice Stake KQC to unlock protocol-fee discounts (tiers) and share a streamed reward pool.
 *         Rewards come ONLY from funded budgets (treasury / protocol fees); nothing is minted.
 *         No yield is promised: the rate depends on how much is funded and how much is staked.
 */
contract KQCStaking is AccessControl, ReentrancyGuard, IFeeDiscount {
    using SafeERC20 for IERC20;

    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

    IERC20 public immutable token;
    uint256 public constant COOLDOWN = 7 days;

    // ---- fee-discount tiers (amounts in wei, discounts in basis points) ----
    uint256[3] public tierMin = [10_000e18, 100_000e18, 1_000_000e18];
    uint256[3] public tierDiscountBps = [1_000, 2_500, 5_000]; // 10%, 25%, 50%

    // ---- staking state ----
    uint256 public totalStaked;
    mapping(address => uint256) public staked;

    struct Pending {
        uint256 amount;
        uint64 unlockAt;
    }
    mapping(address => Pending) public pending;

    // ---- streaming rewards (Synthetix-style) ----
    uint256 public rewardRate;
    uint256 public periodFinish;
    uint256 public lastUpdate;
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    event Staked(address indexed user, uint256 amount);
    event UnstakeRequested(address indexed user, uint256 amount, uint64 unlockAt);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 amount);
    event RewardsFunded(uint256 amount, uint256 duration);

    error ZeroAmount();
    error StillLocked();
    error InsufficientStake();

    constructor(IERC20 _token, address admin) {
        token = _token;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(DISTRIBUTOR_ROLE, admin);
    }

    // ------------------------------------------------------------------ views

    function feeDiscountBps(address user) external view returns (uint256 bps) {
        uint256 s = staked[user];
        for (uint256 i = 3; i > 0; i--) {
            if (s >= tierMin[i - 1]) return tierDiscountBps[i - 1];
        }
        return 0;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return rewardPerTokenStored;
        uint256 applicable = block.timestamp < periodFinish ? block.timestamp : periodFinish;
        return rewardPerTokenStored + ((applicable - lastUpdate) * rewardRate * 1e18) / totalStaked;
    }

    function earned(address user) public view returns (uint256) {
        return (staked[user] * (rewardPerToken() - userRewardPerTokenPaid[user])) / 1e18 + rewards[user];
    }

    // ------------------------------------------------------------------ user actions

    modifier updateReward(address user) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdate = block.timestamp < periodFinish ? block.timestamp : periodFinish;
        if (user != address(0)) {
            rewards[user] = earned(user);
            userRewardPerTokenPaid[user] = rewardPerTokenStored;
        }
        _;
    }

    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        if (amount == 0) revert ZeroAmount();
        totalStaked += amount;
        staked[msg.sender] += amount;
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }

    /// @notice Starts the 7-day cooldown. Unstaking lowers your tier immediately.
    function requestUnstake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        if (amount == 0) revert ZeroAmount();
        if (amount > staked[msg.sender]) revert InsufficientStake();
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        Pending storage p = pending[msg.sender];
        p.amount += amount;
        p.unlockAt = uint64(block.timestamp + COOLDOWN);
        emit UnstakeRequested(msg.sender, amount, p.unlockAt);
    }

    function withdraw() external nonReentrant {
        Pending memory p = pending[msg.sender];
        if (p.amount == 0) revert ZeroAmount();
        if (block.timestamp < p.unlockAt) revert StillLocked();
        delete pending[msg.sender];
        token.safeTransfer(msg.sender, p.amount);
        emit Withdrawn(msg.sender, p.amount);
    }

    function getReward() public nonReentrant updateReward(msg.sender) {
        uint256 r = rewards[msg.sender];
        if (r > 0) {
            rewards[msg.sender] = 0;
            token.safeTransfer(msg.sender, r);
            emit RewardPaid(msg.sender, r);
        }
    }

    // ------------------------------------------------------------------ funding

    /// @notice Fund a reward period. Tokens are pulled from the caller; leftovers roll into the new period.
    function fundRewards(uint256 amount, uint256 duration) external onlyRole(DISTRIBUTOR_ROLE) updateReward(address(0)) {
        require(duration >= 1 days && duration <= 365 days, "bad duration");
        token.safeTransferFrom(msg.sender, address(this), amount);
        if (block.timestamp >= periodFinish) {
            rewardRate = amount / duration;
        } else {
            uint256 leftover = (periodFinish - block.timestamp) * rewardRate;
            rewardRate = (amount + leftover) / duration;
        }
        lastUpdate = block.timestamp;
        periodFinish = block.timestamp + duration;
        emit RewardsFunded(amount, duration);
    }
}
