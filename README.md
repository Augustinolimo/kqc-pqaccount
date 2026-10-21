The signed artwork is kqc-neon-768.png (see SEAL.json). kqc-neon-1024.png is a larger copy for display only.
# kqc-pqaccount

Open-source hybrid post-quantum smart wallet for Ethereum (ERC-4337).

Every transaction needs two signatures, and both must verify:
- ECDSA (classical)
- ML-DSA-65 (NIST FIPS 204, post-quantum)

Keys can be rotated behind a 2-day timelock without changing the wallet address.

## Contracts
- PQAccount.sol: hybrid-signature account and CREATE2 factory
- KQC.sol, KQCStaking.sol, KQCBridge.sol: example token, staking and bridge

## Status
Early draft. These contracts have NOT been compiled in a full toolchain, tested or audited. Do not use them with real funds. On-chain ML-DSA verification needs a precompile or ZK verifier that is not included yet (the account calls an IPQVerifier interface).

## Demo
A browser wallet prototype with real ML-DSA-65 + ECDSA signing (balances and bridge are simulated): https://reliable-madeleine-ba9641.netlify.app

## Licence
MIT
