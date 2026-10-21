// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @dev ERC-4337 v0.7 packed user operation.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice Verifies a post-quantum signature (e.g. ML-DSA-65 / FIPS 204) over a 32-byte digest.
/// Implementations: a native precompile where the chain offers one, or a ZK-wrapped verifier.
interface IPQVerifier {
    function verify(bytes calldata publicKey, bytes32 digest, bytes calldata signature) external view returns (bool);
}

/**
 * @title PQAccount
 * @notice ERC-4337 smart wallet with HYBRID authentication: a transaction is valid only if
 *         BOTH the classical ECDSA signature AND the post-quantum signature verify.
 *         An attacker must break both schemes, so security never drops below today's level
 *         and becomes quantum-resistant as soon as the PQ half is in place.
 *
 * Signature layout:  abi.encode(bytes ecdsaSig, bytes pqPublicKey, bytes pqSig)
 * The PQ public key (1952 bytes for ML-DSA-65) is not stored; only its keccak256 hash is.
 * Key rotation is time-locked and can be cancelled by an optional guardian.
 */
contract PQAccount {
    using ECDSA for bytes32;

    address public immutable entryPoint;

    address public owner;
    bytes32 public pqKeyHash;
    IPQVerifier public pqVerifier;
    address public guardian;

    uint256 public constant ROTATION_DELAY = 2 days;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;

    struct Rotation {
        address newOwner;
        bytes32 newPqKeyHash;
        address newVerifier;
        uint64 readyAt;
    }
    Rotation public pending;

    event Initialized(address indexed owner, bytes32 pqKeyHash, address verifier);
    event RotationProposed(address newOwner, bytes32 newPqKeyHash, address newVerifier, uint64 readyAt);
    event RotationCancelled();
    event RotationFinalized(address newOwner, bytes32 newPqKeyHash, address newVerifier);

    error NotEntryPoint();
    error NotAuthorized();
    error NoPendingRotation();
    error TooEarly();
    error CallFailed(bytes returnData);
    error LengthMismatch();

    modifier onlyEntryPointOrSelf() {
        if (msg.sender != entryPoint && msg.sender != address(this)) revert NotAuthorized();
        _;
    }

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @notice One-time setup (called by the factory right after deployment).
    function initialize(address _owner, bytes32 _pqKeyHash, address _verifier, address _guardian) external {
        require(owner == address(0), "initialized");
        owner = _owner;
        pqKeyHash = _pqKeyHash;
        pqVerifier = IPQVerifier(_verifier);
        guardian = _guardian;
        emit Initialized(_owner, _pqKeyHash, _verifier);
    }

    // ---------------------------------------------------------------- ERC-4337

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        validationData = _validateHybrid(userOpHash, userOp.signature) ? 0 : SIG_VALIDATION_FAILED;
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // EntryPoint verifies the deposit itself
        }
    }

    function execute(address dest, uint256 value, bytes calldata data) external onlyEntryPointOrSelf {
        _call(dest, value, data);
    }

    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata data)
        external
        onlyEntryPointOrSelf
    {
        if (dest.length != value.length || dest.length != data.length) revert LengthMismatch();
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], data[i]);
        }
    }

    // ---------------------------------------------------------------- ERC-1271 (dapp logins)

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _validateHybrid(hash, signature) ? ERC1271_MAGIC : bytes4(0xffffffff);
    }

    // ---------------------------------------------------------------- key rotation

    function proposeRotation(address newOwner, bytes32 newPqKeyHash, address newVerifier) external onlyEntryPointOrSelf {
        uint64 readyAt = uint64(block.timestamp + ROTATION_DELAY);
        pending = Rotation(newOwner, newPqKeyHash, newVerifier, readyAt);
        emit RotationProposed(newOwner, newPqKeyHash, newVerifier, readyAt);
    }

    function cancelRotation() external {
        if (msg.sender != guardian && msg.sender != address(this) && msg.sender != entryPoint) revert NotAuthorized();
        if (pending.readyAt == 0) revert NoPendingRotation();
        delete pending;
        emit RotationCancelled();
    }

    function finalizeRotation() external onlyEntryPointOrSelf {
        Rotation memory r = pending;
        if (r.readyAt == 0) revert NoPendingRotation();
        if (block.timestamp < r.readyAt) revert TooEarly();
        owner = r.newOwner;
        pqKeyHash = r.newPqKeyHash;
        pqVerifier = IPQVerifier(r.newVerifier);
        delete pending;
        emit RotationFinalized(r.newOwner, r.newPqKeyHash, r.newVerifier);
    }

    // ---------------------------------------------------------------- internals

    function _validateHybrid(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        (bytes memory ecdsaSig, bytes memory pqPk, bytes memory pqSig) = abi.decode(signature, (bytes, bytes, bytes));

        // 1) classical half
        (address signer, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(digest), ecdsaSig);
        if (err != ECDSA.RecoverError.NoError || signer != owner) return false;

        // 2) post-quantum half: the supplied key must match the committed hash
        if (keccak256(pqPk) != pqKeyHash) return false;
        return pqVerifier.verify(pqPk, digest, pqSig);
    }

    function _call(address dest, uint256 value, bytes calldata data) internal {
        (bool ok, bytes memory ret) = dest.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
    }

    receive() external payable {}
}

/// @notice Deterministic (CREATE2) factory so a user's wallet address is the same on every EVM chain.
contract PQAccountFactory {
    address public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed owner, bytes32 pqKeyHash);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createAccount(address owner, bytes32 pqKeyHash, address verifier, address guardian, bytes32 salt)
        external
        returns (PQAccount account)
    {
        address predicted = getAddress(owner, pqKeyHash, salt);
        if (predicted.code.length > 0) return PQAccount(payable(predicted));
        // The owner and PQ key hash are mixed into the CREATE2 salt, so nobody can front-run
        // the deployment and claim a user's address with different keys.
        account = new PQAccount{salt: _mix(owner, pqKeyHash, salt)}(entryPoint);
        account.initialize(owner, pqKeyHash, verifier, guardian);
        emit AccountCreated(address(account), owner, pqKeyHash);
    }

    function getAddress(address owner, bytes32 pqKeyHash, bytes32 salt) public view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                _mix(owner, pqKeyHash, salt),
                keccak256(abi.encodePacked(type(PQAccount).creationCode, abi.encode(entryPoint)))
            )
        );
        return address(uint160(uint256(h)));
    }

    function _mix(address owner, bytes32 pqKeyHash, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, pqKeyHash, salt));
    }
}
