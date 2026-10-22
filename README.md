# passkey-wallet-7702

A tiny smart account that lets a **P-256 (secp256r1) key** — the curve passkeys / Secure Enclave / Android Keystore use — control an ordinary Ethereum EOA, via:

- **EIP-7951** `P256VERIFY` precompile at `0x100` (6,900 gas, live on mainnet since Fusaka, 3 Dec 2025)
- **EIP-7702** delegation (`0xef0100 || impl` written to the EOA's code)

## Run
```
forge test -vv
```
`foundry.toml` sets `evm_version = "osaka"`. Under `prague` the precompile doesn't exist and the 4 happy-path tests fail with `BadSignature` — proof that the real precompile is being called (no mocks, no fork).

## What the tests cover
| Test | What it proves |
|---|---|
| test_DelegationIndicatorIsSet | EOA code == `0xef0100 ‖ impl` after `vm.signDelegation` + `vm.attachDelegation` |
| test_PrecompileDirect | raw call to 0x100 returns 1; wrong message returns empty bytes, no revert |
| test_RelayerExecutesWithPasskey | anyone can relay; call arrives `msg.sender == alice` |
| test_ReplayFails / test_SequentialNonces | nonce bumps, same signature can't be reused |
| test_WrongPasskeyFails / test_TamperedCallFails | key and call data are bound |
| test_HighSRejected | malleable high-s twin rejected (EIP-7951 doesn't enforce low-s) |
| test_CrossAccountReplayFails | digest includes `address(this)` + chainid |
| test_InitializeOnlySelf / test_CannotReinitialize | nobody can front-run and plant a key |
| testFuzz_RandomSigFails | random r,s never pass |

## Not production
- Raw P-256 over a digest. Real WebAuthn signs `sha256(authenticatorData ‖ sha256(clientDataJSON))`; you must rebuild that on-chain (challenge check, flags) before calling the precompile.
- Plain storage slots; real 7702 accounts should use namespaced storage (ERC-7201) since re-delegation keeps old storage.
- The EOA's secp256k1 key still has full control — 7702 doesn't remove it.
- No audit.
