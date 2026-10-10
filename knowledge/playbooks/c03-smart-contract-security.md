# C03 (extension) — Smart Contract / Web3 Security

Local source analysis only -- Solidity contracts are analyzed as code
(`smart_contract_scan`, like `sast_scan`), never by sending transactions
to a live contract on mainnet/testnet without separate, explicit
approval (that would be exploitation against a system you may not even
control, since many contracts are immutable once deployed).

## What it is
Smart contract bugs are unusually high-stakes: a deployed contract is
often immutable, so a missed vulnerability can mean permanent,
unrecoverable loss of funds the moment it's exploited by anyone, not
just this engagement.

## Basic
- `smart_contract_scan(path='<repo or .sol file>')` (Slither) against
  any Solidity source in scope -- covers the well-known, high-frequency
  vulnerability classes automatically: reentrancy, unchecked external
  calls, integer overflow/underflow (less common post-Solidity 0.8 which
  has built-in overflow checks, but still relevant for older contracts
  or unchecked blocks), tx.origin misuse for authorization, and
  uninitialized storage pointers.
- Reentrancy specifically: look for any function that makes an external
  call (e.g. transferring ETH/tokens to an address) *before* updating
  its own internal state (e.g. a balance) -- this is the classic
  pattern (the DAO-hack class of bug) that Slither flags directly.

## Intermediate
- Access control review: does every privileged function (minting,
  pausing, upgrading, withdrawing treasury funds) have an explicit
  owner/role check? A missing `onlyOwner`-equivalent modifier on a
  sensitive function is a severe finding even without further
  confirmation.
- Oracle/price-manipulation review: if the contract reads a price from
  an on-chain source (e.g. a DEX pool) rather than a time-weighted or
  decentralized oracle, flag it -- flash-loan-funded price manipulation
  against a single-block spot price is a well-documented, repeatedly
  exploited pattern.
- Upgradability review: if the contract uses a proxy pattern, confirm
  the upgrade function itself has a strict access control and ideally a
  timelock/multisig -- an unprotected upgrade function means anyone can
  replace the entire contract's logic.

## Advanced (approval-gated)
- Confirming an identified bug is actually exploitable (e.g. demonstrating
  a reentrancy drain) requires deploying to a local/test chain (Hardhat/
  Foundry local network, or a public testnet you control test funds on)
  and crafting a PoC transaction -- never against a mainnet contract
  with real funds, and only with explicit approval even in a test
  environment, following the same minimal-PoC discipline as every other
  exploitation step.

## Tools
`smart_contract_scan` (Slither).

## Reporting notes (b01 cross-reference)
PCI DSS v4.0 is essentially never applicable here (no cardholder data).
NIST CSF 2.0 PR.PS and ID.RA (risk assessment -- smart contract risk
should explicitly be part of the organization's risk register given
the immutability stakes). ISO 27001:2022 A.8.28 (Secure Coding). CIS
Controls v8 doesn't have a dedicated Web3 control; Control 16
(Application Security) is the closest fit, IG2. Breach pattern: closest
to Basic Web Application Attacks / System Intrusion depending on
severity, though DBIR's taxonomy predates widespread Web3 adoption and
this is a genuine gap worth noting rather than forcing a fit. ATT&CK
likewise has no mature on-chain-exploit technique family yet -- cite
the specific vulnerability class by name (e.g. "reentrancy," per
Slither's own finding taxonomy) rather than reaching for an ATT&CK ID
that doesn't really apply.
