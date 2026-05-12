# Security Policy

  ## Supported Versions

  This repository contains experimental Bisq MuSig/adaptor-signature protocol,
  wallet, RPC, and test-environment code. Bugs in this repository may affect
  transaction signing, settlement safety, protocol state transitions, wallet fund
  handling, or privacy.

  Security fixes are applied to the active development branch and any active
  maintenance branches currently used by Bisq development or test deployments.

  | Version / Branch | Supported |
  | --- | --- |
  | `main` | :white_check_mark: |
  | Active development or review branches, such as `pr140` while under review | :x: |
  | Branches or commits used by active Bisq MuSig test deployments | :x: |
  | Old commits, unsupported forks, or locally modified builds | :x: |

  This repository does not have stable public releases. Users and integrators
  should treat `main` as the primary supported branch unless maintainers announce
  otherwise.

  ## Reporting a Vulnerability

  Please do **not** report security vulnerabilities through public GitHub issues,
  pull requests, Discussions, Matrix rooms, forums, or social media.

  Report suspected vulnerabilities privately through GitHub's **Report a
  vulnerability** flow on this repository's Security page. If that option is not
  available, contact Bisq maintainers through the main Bisq project security
  channel and ask for a private reporting path. Do not include exploit details in
  public channels.

  Include as much detail as possible:

  - affected branch, commit, crate, protocol document, RPC endpoint, or test
    environment;
  - affected component, such as `protocol`, `wallet`, `rpc`, `mem`, `testenv`,
    PSBT handling, MuSig/adaptor-signature flow, swap transaction construction,
    script paths, wallet service, storage, or chain-access logic;
  - whether the issue affects key aggregation, nonce generation or reuse,
    adaptor-signature correctness, partial signature validation, PSBT validation,
    transaction construction, timelocks, refund paths, settlement, watchtower
    behavior, silent payments, fee accounting, or protocol state transitions;
  - whether the issue can cause loss of funds, unauthorized signing, signature
    forgery, nonce/key leakage, stuck funds, incorrect payout/refund, privacy
    leakage, denial of settlement, or state desynchronization between peers;
  - reproduction steps, logs, test vectors, malformed protocol messages, PSBTs,
    transactions, scripts, or proof of concept code where useful;
  - whether the issue depends on a malicious peer, malicious RPC client, chain
    reorganization, mempool policy behavior, invalid oracle/chain data, replayed
    messages, concurrent sessions, crash/restart state recovery, or compromised
    local storage.

  Bisq is an open-source project maintained by contributors. Response times may
  vary, but reports involving possible loss of funds, unauthorized signing, nonce
  reuse, key material exposure, invalid settlement, incorrect refund behavior,
  signature validation bypass, or exploitable protocol-state desynchronization are
  treated as urgent security issues and will be triaged as quickly as possible.

  For lower-severity issues, maintainers will respond when contributor capacity is
  available.

  If the report is accepted, maintainers may coordinate a fix privately, prepare a
  patched branch, update protocol documentation and tests, and publish an advisory
  after users or test operators have had a reasonable opportunity to update. If the
  report is declined, maintainers will explain the reason when possible.

  Please give maintainers reasonable time to investigate and release mitigations
  before public disclosure. For severe or actively exploitable issues, coordinate
  timing with maintainers so public details do not increase risk to users.

  Bisq does not currently guarantee a bug bounty. Security work may be eligible
  for Bisq DAO compensation if it qualifies under the project's contributor and
  critical-bug processes.
