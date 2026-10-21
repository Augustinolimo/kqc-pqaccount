// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IFeeDiscount} from "./KQCStaking.sol";

interface IKQCMintBurn is IERC20 {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
}

/**
 * @title KQCBridge
 * @notice Moves KQC between chains.
 *   HOME chain      -> mode LockRelease : lock on the way out, release on the way in.
 *   SATELLITE chain -> mode MintBurn    : burn on the way out, mint on the way in.
 * Inbound transfers need M-of-N guardian attestations (EIP-712). Per-transfer and rolling
 * 24h limits cap the blast radius of any compromise, and guardians can pause instantly.
 * Recipients are bytes32 so non-EVM chains (Solana, Cosmos, ...) can be addressed.
 *
 * Quantum upgrade path: guardian attestations are ECDSA today; the contract is deployed behind
 * a time-locked admin so the attestation check can be swapped for a PQ verifier (see IPQVerifier).
 */
contract KQCBridge is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    enum Mode { LockRelease, MintBurn }

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 private constant BRIDGE_IN_TYPEHASH =
        keccak256("BridgeIn(uint256 srcChainId,uint256 srcNonce,address recipient,uint256 amount)");

    IKQCMintBurn public immutable token;
    Mode public immutable mode;
    IFeeDiscount public staking;
    address public treasury;

    // fees
    uint256 public feeBps = 10; // 0.10%
    uint256 public constant MAX_FEE_BPS = 100; // hard ceiling 1%

    // limits
    uint256 public perTxLimit = 500_000e18;
    uint256 public dailyLimit = 5_000_000e18;
    uint256 public windowStart;
    uint256 public windowUsed;

    // guardians
    mapping(address => bool) public isGuardian;
    uint256 public guardianCount;
    uint256 public threshold;

    uint256 public outNonce;
    mapping(bytes32 => bool) public processed;

    event BridgeOut(uint256 indexed nonce, uint256 indexed dstChainId, address indexed sender, bytes32 recipient, uint256 amount, uint256 fee);
    event BridgeIn(uint256 indexed srcChainId, uint256 indexed srcNonce, address indexed recipient, uint256 amount);
    event GuardianSet(address indexed guardian, bool active);
    event ThresholdSet(uint256 threshold);

    error LimitExceeded();
    error AlreadyProcessed();
    error BadSignatures();
    error BadConfig();
    error ZeroAmount();

    constructor(IKQCMintBurn _token, Mode _mode, address admin, address _treasury, IFeeDiscount _staking)
        EIP712("KQCBridge", "1")
    {
        token = _token;
        mode = _mode;
        treasury = _treasury;
        staking = _staking;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ------------------------------------------------------------------ outbound

    function bridgeOut(uint256 dstChainId, bytes32 recipient, uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (amount > perTxLimit) revert LimitExceeded();

        uint256 fee = _fee(msg.sender, amount);
        uint256 net = amount - fee;

        IERC20(address(token)).safeTransferFrom(msg.sender, address(this), amount);
        if (fee > 0) IERC20(address(token)).safeTransfer(treasury, fee);
        if (mode == Mode.MintBurn) token.burn(net); // lock mode keeps `net` in the contract

        uint256 n = ++outNonce;
        emit BridgeOut(n, dstChainId, msg.sender, recipient, net, fee);
    }

    function quoteFee(address user, uint256 amount) external view returns (uint256) {
        return _fee(user, amount);
    }

    // ------------------------------------------------------------------ inbound

    /// @param signatures guardian EIP-712 signatures, ordered by ascending signer address (no duplicates)
    function bridgeIn(uint256 srcChainId, uint256 srcNonce, address recipient, uint256 amount, bytes[] calldata signatures)
        external
        nonReentrant
        whenNotPaused
    {
        if (amount == 0) revert ZeroAmount();
        if (amount > perTxLimit) revert LimitExceeded();
        bytes32 id = keccak256(abi.encode(srcChainId, srcNonce));
        if (processed[id]) revert AlreadyProcessed();

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(BRIDGE_IN_TYPEHASH, srcChainId, srcNonce, recipient, amount)));
        _checkSignatures(digest, signatures);

        _consumeDailyLimit(amount);
        processed[id] = true;

        if (mode == Mode.LockRelease) {
            IERC20(address(token)).safeTransfer(recipient, amount);
        } else {
            token.mint(recipient, amount);
        }
        emit BridgeIn(srcChainId, srcNonce, recipient, amount);
    }

    // ------------------------------------------------------------------ admin (put behind a timelock + multisig)

    function setGuardian(address g, bool active) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (isGuardian[g] == active) return;
        isGuardian[g] = active;
        guardianCount = active ? guardianCount + 1 : guardianCount - 1;
        if (threshold > guardianCount) revert BadConfig();
        emit GuardianSet(g, active);
    }

    function setThreshold(uint256 t) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (t == 0 || t > guardianCount) revert BadConfig();
        threshold = t;
        emit ThresholdSet(t);
    }

    function setLimits(uint256 _perTx, uint256 _daily) external onlyRole(DEFAULT_ADMIN_ROLE) {
        perTxLimit = _perTx;
        dailyLimit = _daily;
    }

    function setFee(uint256 bps, address _treasury, IFeeDiscount _staking) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bps > MAX_FEE_BPS) revert BadConfig();
        feeBps = bps;
        treasury = _treasury;
        staking = _staking;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ------------------------------------------------------------------ internals

    function _fee(address user, uint256 amount) internal view returns (uint256) {
        uint256 base = (amount * feeBps) / 10_000;
        if (address(staking) == address(0)) return base;
        uint256 discount = staking.feeDiscountBps(user);
        return (base * (10_000 - discount)) / 10_000;
    }

    function _checkSignatures(bytes32 digest, bytes[] calldata sigs) internal view {
        if (threshold == 0 || sigs.length < threshold) revert BadSignatures();
        address last = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            address signer = ECDSA.recover(digest, sigs[i]);
            if (signer <= last || !isGuardian[signer]) revert BadSignatures();
            last = signer;
        }
    }

    function _consumeDailyLimit(uint256 amount) internal {
        if (block.timestamp >= windowStart + 1 days) {
            windowStart = block.timestamp;
            windowUsed = 0;
        }
        windowUsed += amount;
        if (windowUsed > dailyLimit) revert LimitExceeded();
    }
}
