// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Pausable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title Kenya Quantum Coin (KQC)
 * @notice Fixed-cap ERC-20 with gasless approvals (EIP-2612), on-chain governance votes,
 *         emergency pause and a bridge-only mint role for satellite chains.
 *
 * Deployment modes
 *  - HOME chain:      initialSupply = MAX_SUPPLY, minted once to the treasury/vesting set-up. No MINTER_ROLE granted.
 *  - SATELLITE chain: initialSupply = 0, MINTER_ROLE granted to the KQCBridge (mint/burn mode).
 *    Total supply across all chains can never exceed MAX_SUPPLY because satellite mints are
 *    backed 1:1 by tokens locked in the home-chain bridge.
 *
 * Quantum note: this contract is signature-agnostic. Quantum resistance for holders comes from
 * using PQAccount (hybrid ECDSA + ML-DSA) as the wallet. See PQAccount.sol.
 */
contract KQC is ERC20, ERC20Burnable, ERC20Pausable, ERC20Permit, ERC20Votes, AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    uint256 public constant MAX_SUPPLY = 1_000_000_000e18;

    error CapExceeded();

    constructor(address admin, address initialHolder, uint256 initialSupply)
        ERC20("Kenya Quantum Coin", "KQC")
        ERC20Permit("Kenya Quantum Coin")
    {
        if (initialSupply > MAX_SUPPLY) revert CapExceeded();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        if (initialSupply > 0) _mint(initialHolder, initialSupply);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Bridge-only. Reverts if the global cap would be exceeded.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (totalSupply() + amount > MAX_SUPPLY) revert CapExceeded();
        _mint(to, amount);
    }

    // ---- required overrides (OpenZeppelin v5) ----

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable, ERC20Votes)
    {
        super._update(from, to, value);
    }

    function nonces(address owner) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }
}
