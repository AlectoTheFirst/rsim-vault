# CLAUDE.md

Instructions for Claude Code in this repository.

## Product

`rsim-vault` is a show command dump. A collector runs a managed list of commands on each device. The tool stores each answer verbatim and encrypted. An API and a portal give the stored answers to the users who have the permission.

`rsim-vault` is a standalone tool. It is not a digital twin and not a database of network state.

## Public repository

- This repository is public. Do not commit an answer of a real device, a real config, a private key, a credential or a host name of the infrastructure of the owner.
- Test fixtures use only documentation addresses and documentation MAC addresses. A fixture config has fake secrets. Tests make their keys and certificates at test time.
- Each GitHub action is pinned by its commit SHA, with the release tag as a comment.

## Rules of the product

- No user sends a command to a device.
- The tool manages the commands in one central catalog.
- Only a user with the permission `cmd-manager` adds a command to the catalog.
- Only a user with the permission `cmd-manager` does a test of a new command and reads its answer. An admin does not have this right.
- A user asks which answers exist for a device. The reply lists each stored command of that device.
- Each answer is raw. The tool stores an answer as is and gives it back as is.
- The tool does not parse an answer and keeps no table of its content. The answer of a routing table command is stored as text.
- The tool masks nothing in an answer.
- Each command of a device is a separate bundle.
- All users read one estate of devices.
- A catalog command that prints a text file reads a file of a device. The tool has no file transfer.
- A controller with an HTTPS API is a source for the devices that it manages. A command of the catalog reads the data of one device from the controller. The answer is stored for that device, and a user reads it by that device.

## Sign-in and permissions

- Users and tools sign in through OIDC. The identity provider gives the groups of a user or a tool in the token.
- The identity provider gives the group `cmd-manager`.
- Each command of the catalog has a class. A command whose answer holds secrets, such as a running config, has a class of its own.
- A read permission names a device group and a class of commands.
- An admin manages the devices, the device groups and the device credentials. An admin reads no answer without a read permission.

## Encryption

- The tool encrypts each bundle locally before the upload. Each bundle has a random data key.
- A KMS key for each command class wraps the data key of a bundle of that class.
- KMS opens a data key only for a caller whose token has the class. The code of the API applies the device group.
- The collector can make a data key and cannot open one.
- The test answers of a command have a KMS key of their own, which opens only for a caller with the group `cmd-manager`.
- A KMS key of its own wraps each device credential. Only the role of the collector can open it.
- The store is an S3 bucket of AWS. The bucket encrypts each object with a customer managed KMS key, which is a separate key.
- No compliance rule sets the cipher of the local encryption.

## Store and collection

- PostgreSQL holds the management data and the index of the stored answers.
- An index record holds the device, the command, the time of the read, the status and the name of the bundle.
- A read whose answer has the same bytes as the last stored answer of the device and the command writes only an index record.
- The command manager sets the interval and the retention of each command. A command has no default for them.
- The collector removes the terminal control bytes, the echo of the command, the prompt and the pager marks from an answer before the store.

## Crates

| Crate | Content |
|---|---|
| `rsim-vault-store` | The encrypted bundles and their keys |
| `rsim-vault-inventory` | The devices, the credentials, the users and the command catalog |
| `rsim-vault-collect` | The collector: a library and the binary `rsim-vault-collect` |
| `rsim-vault` | The binary of the API and the portal |

## Commands

| Task | Command |
|---|---|
| Format check | `cargo fmt --all --check` |
| Lint | `cargo clippy --workspace --all-targets --locked` |
| All tests | `cargo test --workspace --locked` |
| Advisories of the locked dependencies | `cargo audit` |

CI is in `.github/workflows/ci.yml` with the jobs `check`, `audit` and `secrets`. `.github/workflows/codeql.yml` runs the CodeQL analysis of Actions and Rust.

## Where to build

- Build and test in CI only. This covers each `cargo build`, `cargo test` and `cargo clippy`.
- Allowed on the laptop of the owner: editing and `cargo fmt`.

## Open points

Do not make this decision silently. Ask the owner.

- The licence of the repository
